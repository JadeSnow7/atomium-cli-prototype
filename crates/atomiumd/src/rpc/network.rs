use anyhow::Result;
use atomium_gateway::{
    normalize_allowlist_pattern, spawn_run_proxy_with_policy, EgressProxyHandle,
};
use atomium_protocol::RunStartRequest;

pub(crate) fn validate_egress_request(
    req: &RunStartRequest,
) -> std::result::Result<(), (i32, String)> {
    if req.allowed_egress_hosts.len() > 64 {
        return Err((-32602, "too many allowed egress hosts (max 64)".into()));
    }
    if req
        .allowed_egress_hosts
        .iter()
        .any(|host| normalize_allowlist_pattern(host).is_none())
    {
        return Err((-32602, "allowed egress host entries are invalid".into()));
    }
    if req.upstream_proxy_addr.as_deref().is_some_and(|addr| {
        addr.is_empty() || addr.len() > 255 || addr.chars().any(char::is_control)
    }) {
        return Err((-32602, "upstream_proxy_addr is invalid".into()));
    }
    Ok(())
}

pub(crate) async fn start_run_egress_proxy(
    run_id: &str,
    ephemeral_token: &str,
    req: &RunStartRequest,
) -> Result<EgressProxyHandle> {
    let allowlist = if req.allowed_egress_hosts.is_empty() {
        None
    } else {
        Some(req.allowed_egress_hosts.clone())
    };
    spawn_run_proxy_with_policy(
        run_id,
        ephemeral_token,
        req.upstream_proxy_addr.clone(),
        allowlist,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_req() -> RunStartRequest {
        RunStartRequest {
            profile_id: "p1".into(),
            program: "/bin/echo".into(),
            args: vec![],
            env: HashMap::new(),
            workspace_id: None,
            upstream_proxy_addr: None,
            allowed_egress_hosts: vec![],
            timeout_ms: None,
        }
    }

    #[test]
    fn rejects_invalid_allowlist_and_upstream_proxy() {
        assert!(validate_egress_request(&sample_req()).is_ok());

        let mut bad_host = sample_req();
        bad_host.allowed_egress_hosts = vec!["http://bad host/path".into()];
        assert_eq!(validate_egress_request(&bad_host).unwrap_err().0, -32602);

        let mut too_many = sample_req();
        too_many.allowed_egress_hosts = (0..65).map(|i| format!("host{i}.example.com")).collect();
        assert_eq!(validate_egress_request(&too_many).unwrap_err().0, -32602);

        let mut empty_upstream = sample_req();
        empty_upstream.upstream_proxy_addr = Some(String::new());
        assert_eq!(
            validate_egress_request(&empty_upstream).unwrap_err().0,
            -32602
        );

        let mut ctrl_upstream = sample_req();
        ctrl_upstream.upstream_proxy_addr = Some("127.0.0.1:8080\n".into());
        assert_eq!(
            validate_egress_request(&ctrl_upstream).unwrap_err().0,
            -32602
        );
    }
}
