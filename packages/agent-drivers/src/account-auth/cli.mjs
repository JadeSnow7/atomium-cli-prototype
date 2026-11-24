import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { createDefaultAccountService, LeaseConflictError } from './account-service.mjs';

const ACCOUNT_USAGE = [
  'Usage:',
  '  node atomium.mjs account capture <profile_id> [--name "..."] [--mode hostKeychainSlot|isolatedFile] [--proxy http://...] [--tz ...] [--lang ...]',
  '  node atomium.mjs account list',
  '  node atomium.mjs account switch <profile_id>',
  '  node atomium.mjs account run <profile_id> -- <agy args...>',
].join('\n');

function formatTable(headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i] ?? '').length)),
  );
  const renderRow = (cols) =>
    cols.map((c, i) => String(c ?? '').padEnd(widths[i])).join('  ');
  const sep = widths.map((w) => '-'.repeat(w)).join('  ');
  return [renderRow(headers), sep, ...rows.map(renderRow)].join('\n');
}

function parseCaptureFlags(rest) {
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i];
    const val = rest[i + 1];
    if (val === undefined || val.startsWith('--')) {
      throw new Error(`missing-flag-value:${flag}`);
    }
    if (flag === '--name') {
      opts.displayName = val;
    } else if (flag === '--mode') {
      opts.credentialMode = val;
    } else if (flag === '--proxy') {
      opts.proxyURL = val;
    } else if (flag === '--tz') {
      opts.timezone = val;
    } else if (flag === '--lang') {
      opts.lang = val;
    } else if (flag === '--service') {
      opts.credentialSlot = { ...(opts.credentialSlot || {}), service: val };
    } else if (flag === '--account') {
      opts.credentialSlot = { ...(opts.credentialSlot || {}), account: val };
    } else if (flag === '--fallback-rel-path') {
      opts.credentialSlot = { ...(opts.credentialSlot || {}), fallbackRelPath: val };
    } else {
      throw new Error(`unknown-flag:${flag}`);
    }
    i++;
  }
  return opts;
}

export async function runAccountCli(args, { rootDir }) {
  const [op, ...rest] = args;

  if (!op || op === '--help' || op === '-h') {
    console.log(ACCOUNT_USAGE);
    return op ? 0 : 64;
  }

  const ctx = createDefaultAccountService({ runsDir: join(rootDir, 'runs') });
  try {
    if (op === 'capture') {
      const [profileId, ...flagArgs] = rest;
      if (!profileId || profileId.startsWith('--')) {
        console.error(ACCOUNT_USAGE);
        return 64;
      }
      let opts;
      try {
        opts = parseCaptureFlags(flagArgs);
      } catch (err) {
        console.error(`Account capture argument error: ${err.message}`);
        console.error(ACCOUNT_USAGE);
        return 64;
      }
      const result = await ctx.service.captureProfile(profileId, opts);
      console.log(JSON.stringify(result, null, 2));
      return 0;
    }

    if (op === 'list') {
      if (rest.length !== 0) {
        console.error(ACCOUNT_USAGE);
        return 64;
      }
      const { profiles } = ctx.service.listProfiles();
      if (profiles.length === 0) {
        console.log('No account profiles captured yet. Run: node atomium.mjs account capture <profile_id>');
        return 0;
      }
      const headers = ['ACTIVE', 'PROFILE_ID', 'NAME', 'MODE', 'PROXY', 'STATE / LOCK', 'VER'];
      const rows = profiles.map((p) => {
        const lockDesc = p.locked
          ? `${p.state} [LOCKED pid=${p.lock.holderPid} run=${p.lock.runId}]`
          : `${p.state} (idle)`;
        return [
          p.active ? '*' : '',
          p.id,
          p.displayName,
          p.credentialMode,
          p.proxyURL || '-',
          lockDesc,
          `v${p.snapshotVersion}`,
        ];
      });
      console.log(formatTable(headers, rows));
      return 0;
    }

    if (op === 'switch') {
      if (rest.length !== 1 || rest[0].startsWith('--')) {
        console.error(ACCOUNT_USAGE);
        return 64;
      }
      const profileId = rest[0];
      const res = await ctx.service.switchProfile(profileId);
      console.log(JSON.stringify(res, null, 2));
      return 0;
    }

    if (op === 'run') {
      const profileId = rest[0];
      const sepIdx = rest.indexOf('--');
      if (!profileId || profileId.startsWith('--') || sepIdx !== 1 || rest.length < 3) {
        console.error(ACCOUNT_USAGE);
        return 64;
      }
      const agyArgs = rest.slice(sepIdx + 1);
      const res = await ctx.service.runWithProfile(profileId, agyArgs, { stdio: 'inherit' });
      if (res.tokenRefreshed) {
        console.error(
          `[atomium] Refreshed credential persisted to vault for profile=${res.profileId} (v${res.snapshotVersion}, sha256=${res.contentDigest.slice(0, 12)}...)`,
        );
      }
      return res.exitCode ?? (res.signal ? 1 : 0);
    }

    console.error(ACCOUNT_USAGE);
    return 64;
  } catch (err) {
    if (err instanceof LeaseConflictError || err?.code === 'LEASE_CONFLICT') {
      console.error(
        `Account busy: resource=${err.conflict.resourceKey} is locked by run_id=${err.conflict.runId} (pid=${err.conflict.holderPid}).`,
      );
      return 2;
    }
    const safeReason = typeof err?.message === 'string' ? err.message : 'account-operation-failed';
    console.error(`Account error: ${safeReason}`);
    return 1;
  } finally {
    ctx.close();
  }
}

export async function verifyAccountSwitch(rootDir) {
  const testFile = join(rootDir, 'account-auth', 'account-auth.test.mjs');
  const exitCode = await new Promise((resolveExit, rejectExit) => {
    const child = spawn(process.execPath, ['--test', testFile], {
      cwd: rootDir,
      stdio: 'inherit',
    });
    child.once('error', rejectExit);
    child.once('exit', (code) => resolveExit(code ?? 1));
  });
  const passed = exitCode === 0;
  console.log(
    passed
      ? 'PASS verify-account-switch: all 6 multi-account credential, switching, concurrency, and crash-recovery checks passed.'
      : 'FAIL verify-account-switch: one or more multi-account checks failed.',
  );
  return passed;
}
