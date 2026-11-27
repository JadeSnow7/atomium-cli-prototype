use anyhow::{anyhow, Result};
use atomium_core::{
    decode_agy_oauth_for_file, default_agy_oauth_mode, encode_agy_oauth_for_keychain,
    validate_agy_oauth_payload, LeaseMode, LeaseRequest,
};
use atomium_protocol::{
    CredentialSpec, EgressBinding, IdentityProfile, LocalePolicy, OAuthStorageMode, ProfileState,
    SubscriptionActivateRequest, SubscriptionCaptureRequest, SubscriptionSummary,
};
use base64::Engine;

use crate::state::{host_slot_key, DaemonState};

const MAX_CAPTURED_SECRET_BYTES: usize = 256 * 1024;

fn validate_identifier(kind: &str, id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!("invalid {kind}: must be 1..64 [A-Za-z0-9_-] chars"));
    }
    Ok(())
}

pub(crate) fn handle_profiles_list(state: &DaemonState) -> Result<Vec<IdentityProfile>> {
    state.profiles.list()
}

pub(crate) fn handle_profiles_upsert(state: &DaemonState, profile: &IdentityProfile) -> Result<()> {
    state.profiles.upsert(profile)
}

pub(crate) fn handle_subscriptions_capture(
    state: &DaemonState,
    req: SubscriptionCaptureRequest,
) -> std::result::Result<SubscriptionSummary, (i32, String)> {
    validate_identifier("profile_id", &req.profile_id).map_err(|e| (-32602, e.to_string()))?;
    if req.display_name.trim().is_empty() {
        return Err((-32602, "display_name must not be empty".into()));
    }

    let storage_mode = req.storage_mode.unwrap_or_else(default_agy_oauth_mode);
    let Some(raw_secret_b64) = &req.raw_secret_b64 else {
        return Err((-32602, "raw_secret_b64 is required".into()));
    };
    let raw_secret = base64::engine::general_purpose::STANDARD
        .decode(raw_secret_b64.trim())
        .map_err(|_| (-32602, "invalid base64 in raw_secret_b64".into()))?;

    if raw_secret.is_empty() {
        return Err((-32602, "captured oauth credential payload is empty".into()));
    }
    if raw_secret.len() > MAX_CAPTURED_SECRET_BYTES {
        return Err((
            -32602,
            "captured oauth credential payload exceeds daemon size limit".into(),
        ));
    }

    let canonical_bytes =
        decode_agy_oauth_for_file(&raw_secret).map_err(|e| (-32602, e.to_string()))?;
    if canonical_bytes.len() > MAX_CAPTURED_SECRET_BYTES {
        return Err((
            -32602,
            "canonical oauth credential payload exceeds daemon size limit".into(),
        ));
    }
    validate_agy_oauth_payload(&canonical_bytes)
        .map_err(|e| (-32602, format!("invalid oauth credential payload: {e}")))?;

    // Reclaim stale leases and acquire exclusive OAuth lease so recapture cannot race with
    // an active run holding the same profile or host keychain slot.
    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;
    let mut capture_leases = vec![LeaseRequest {
        resource_key: format!("profile:{}:oauth", req.profile_id),
        mode: LeaseMode::Exclusive,
    }];
    if let OAuthStorageMode::HostKeychainSlot { service, account } = &storage_mode {
        capture_leases.push(LeaseRequest {
            resource_key: format!("host:keychain:{service}:{account}"),
            mode: LeaseMode::Exclusive,
        });
    }
    let capture_run_id = format!("capture-{}", uuid::Uuid::now_v7());
    state
        .leases
        .acquire_all(&capture_run_id, capture_leases, 30)
        .map_err(|e| (-32009, e.to_string()))?;

    let capture_res = (|| -> std::result::Result<SubscriptionSummary, (i32, String)> {
        let existing = state
            .profiles
            .get(&req.profile_id)
            .map_err(|e| (-32000, e.to_string()))?;
        let (vault_blob_id, next_version) = match existing.as_ref().map(|p| &p.credential) {
            Some(CredentialSpec::OauthSnapshot {
                vault_blob_id,
                snapshot_version,
                ..
            }) => (vault_blob_id.clone(), snapshot_version + 1),
            _ => (format!("oauth_{}", req.profile_id), 1),
        };

        let content_digest = state
            .vault
            .write_blob(&vault_blob_id, &canonical_bytes)
            .map_err(|e| (-32000, e.to_string()))?;

        let profile = IdentityProfile {
            id: req.profile_id.clone(),
            display_name: req.display_name,
            agent_kind: req.agent_kind.unwrap_or_else(|| "antigravity".into()),
            credential: CredentialSpec::OauthSnapshot {
                vault_blob_id,
                mode: storage_mode.clone(),
                snapshot_version: next_version,
                content_digest,
            },
            egress: EgressBinding {
                upstream_proxy_id: req.upstream_proxy_id,
                fail_closed: true,
            },
            locale_policy: LocalePolicy {
                timezone: req.timezone,
                lang: req.lang,
            },
            state: ProfileState::Active,
        };

        state
            .profiles
            .upsert(&profile)
            .map_err(|e| (-32000, e.to_string()))?;

        if let OAuthStorageMode::HostKeychainSlot { service, account } = &storage_mode {
            let slot_key = host_slot_key(service, account);
            let _ = state.runs.set_active_host_slot(&slot_key, &profile.id);
        }

        let leases = state
            .leases
            .list_active_leases()
            .map_err(|e| (-32000, e.to_string()))?;
        Ok(state.build_subscription_summary(&profile, &leases))
    })();

    let _ = state.leases.release_all(&capture_run_id);
    capture_res
}

pub(crate) fn handle_subscriptions_list(state: &DaemonState) -> Result<Vec<SubscriptionSummary>> {
    let _ = state.leases.reclaim_stale_leases(Some(&state.profiles))?;
    let profiles = state.profiles.list()?;
    let active_leases = state.leases.list_active_leases()?;
    Ok(profiles
        .iter()
        .map(|p| state.build_subscription_summary(p, &active_leases))
        .collect())
}

pub(crate) fn handle_subscriptions_activate(
    state: &DaemonState,
    req: SubscriptionActivateRequest,
) -> std::result::Result<serde_json::Value, (i32, String)> {
    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;

    let target = state
        .profiles
        .get(&req.profile_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or_else(|| (-32004, format!("profile not found: {}", req.profile_id)))?;

    if target.state != ProfileState::Active {
        return Err((
            -32002,
            format!(
                "profile {} cannot be activated while in state {:?}",
                target.id, target.state
            ),
        ));
    }

    let CredentialSpec::OauthSnapshot {
        vault_blob_id,
        mode,
        ..
    } = &target.credential
    else {
        return Err((
            -32602,
            format!("profile {} does not use oauth_snapshot", target.id),
        ));
    };

    match mode {
        OAuthStorageMode::IsolatedFile { relative_home_path } => Ok(serde_json::json!({
            "activated": true,
            "profile_id": target.id,
            "mode": "isolated_file",
            "relative_home_path": relative_home_path,
            "previous_profile_id": serde_json::Value::Null,
            "previous_writeback": false
        })),
        OAuthStorageMode::HostKeychainSlot { service, account } => {
            let slot_key = host_slot_key(service, account);
            let prev_id = state
                .runs
                .get_active_host_slot(&slot_key)
                .map_err(|e| (-32000, e.to_string()))?;

            let mut lease_reqs = vec![
                LeaseRequest {
                    resource_key: format!("host:keychain:{service}:{account}"),
                    mode: LeaseMode::Exclusive,
                },
                LeaseRequest {
                    resource_key: format!("profile:{}:oauth", target.id),
                    mode: LeaseMode::Exclusive,
                },
            ];
            if let Some(prev) = &prev_id {
                if prev != &target.id {
                    lease_reqs.push(LeaseRequest {
                        resource_key: format!("profile:{prev}:oauth"),
                        mode: LeaseMode::Exclusive,
                    });
                }
            }

            let activate_run_id = format!("activate-{}", uuid::Uuid::now_v7());
            state
                .leases
                .acquire_all(&activate_run_id, lease_reqs, 30)
                .map_err(|e| (-32009, e.to_string()))?;

            let activate_result = (|| -> std::result::Result<serde_json::Value, (i32, String)> {
                let mut previous_writeback = false;
                if let Some(prev) = &prev_id {
                    if prev != &target.id {
                        previous_writeback = state
                            .writeback_host_slot_if_refreshed(prev, service, account)
                            .map_err(|e| (-32000, e.to_string()))?;
                    }
                }

                let target_secret = state
                    .vault
                    .read_blob(vault_blob_id)
                    .map_err(|e| (-32000, e.to_string()))?;
                let encoded = encode_agy_oauth_for_keychain(&target_secret);
                state
                    .keychain
                    .write_generic_password(service, account, &encoded)
                    .map_err(|e| (-32000, e.to_string()))?;

                state
                    .runs
                    .set_active_host_slot(&slot_key, &target.id)
                    .map_err(|e| (-32000, e.to_string()))?;

                Ok(serde_json::json!({
                    "activated": true,
                    "profile_id": target.id,
                    "mode": "host_keychain_slot",
                    "previous_profile_id": prev_id,
                    "previous_writeback": previous_writeback
                }))
            })();

            let _ = state.leases.release_all(&activate_run_id);
            activate_result
        }
    }
}
