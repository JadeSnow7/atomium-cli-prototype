import { lstat, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAgyLoginAdapter } from './agy-acp.mjs';
import { addProfile, addPendingAgyProfile, listProfiles, loadProfile, publicProfile, registerHarnessLogin } from './agent-profiles.mjs';
import { runSelectedProfile } from './agent-profile-audit.mjs';

const runs = fileURLToPath(new URL('./runs',import.meta.url));
const denied = async (run, reason) => {
  try { await run(); return false; } catch(e) { return e.message === reason; }
};
export async function verifyProfileLogin() {
  await mkdir(runs,{recursive:true,mode:0o700});
  if (!(await lstat(runs)).isDirectory() || await realpath(runs)!==runs) throw new Error('unsafe-run-root');
  const dir = await mkdtemp(join(runs,'profile-login-'));
  const checks = [];
  const add = (id,pass) => checks.push({id,pass:Boolean(pass)});
  const root = join(dir,'fixture-store');
  const mockSecret = 'ATOMIUM_SYNTHETIC_TOKEN_DO_NOT_STORE';
  const ready = Object.freeze({status:'ready',sessionReady:true,promptSent:false,identityStatus:'identity-unavailable',
    discardedTestData:mockSecret});
  let calls = 0;
  const run = (id, overrides = {}) => registerHarnessLogin(root,{harness:'agy',id,interactive:true,
    authenticate:async () => { calls++; return ready; },...overrides});
  add('unsupported-harness-refuses-before-driver',
    await denied(()=>run('unsupported',{harness:'codex'}),'unsupported-login-harness') && calls===0);
  add('no-terminal-refuses-before-driver',
    await denied(()=>run('notty',{interactive:false}),'login-requires-terminal') && calls===0);
  await addProfile(root,'synthetic');
  add('never-overwrite-existing-profile',
    await denied(()=>run('synthetic'),'profile-already-exists') && calls===0);
  for (const status of ['cancelled','login-failed','auth-required','probe-failed']) {
    const outcome=await run(status,{authenticate:async ()=>({status,detail:mockSecret})});
    add('does-not-save-'+status,outcome.status===status && outcome.saved===false && !JSON.stringify(outcome).includes(mockSecret) &&
      await denied(()=>loadProfile(root,status),'profile-not-found'));
  }
  const canceled = new AbortController();
  const aborted = await run('aborted',{signal:canceled.signal,authenticate:async ()=>{canceled.abort();return ready;}});
  add('abort-before-publication-does-not-save',aborted.status==='cancelled' &&
    await denied(()=>loadProfile(root,'aborted'),'profile-not-found'));
  const misleading=await run('unconfirmed',{authenticate:async ()=>({...ready,sessionReady:false})});
  add('requires-ready-session-not-only-login-exit',misleading.status==='probe-failed' &&
    await denied(()=>loadProfile(root,'unconfirmed'),'profile-not-found'));

  let entered, release;
  const pending=new Promise(ok=>{entered=ok;});
  const go=new Promise(ok=>{release=ok;});
  let expectedSlot=false;
  const first=run('work',{authenticate:async path=>{expectedSlot=path===join(root,'.agy-host-state');entered();await go;return ready;}});
  await Promise.race([pending,first]);
  try { add('concurrent-login-locks-single-slot',await denied(()=>run('concurrent'),'agy-login-busy')); }
  finally { release(); }
  const success=await first;
  const saved=await loadProfile(root,'work');
  const text=await readFile(join(root,'work.json'),'utf8');
  add('successful-flow-saves-only-reference-and-readiness',expectedSlot && success.saved && success.status==='saved' &&
    saved.credentialRef==='agy:os-keyring-single-slot' && JSON.stringify(success.profile)===JSON.stringify(publicProfile(saved)) &&
    success.profile.identityStatus==='identity-unavailable' && success.profile.isolatedExecution===false &&
    !text.includes(mockSecret) && !JSON.stringify(success).includes(mockSecret));
  add('second-agy-profile-refused-before-driver',
    await denied(()=>run('second'),'agy-single-login-slot') && calls===0);
  add('saved-login-does-not-enable-isolated-agy-execution',
    await denied(()=>runSelectedProfile(saved),'profile-isolated-execution-unavailable'));
  add('synthetic-and-login-profiles-list-together',(await listProfiles(root)).map(p=>p.agent).join(',')==='synthetic-worker,agy');
  const pendingSecond=await addPendingAgyProfile(root,'personal');
  add('new-pending-profile-coexists-with-active-slot',publicProfile(pendingSecond).authentication==='pending-official-login'&&
    pendingSecond.credentialRef===null&&pendingSecond.digest!==(await loadProfile(root,'work')).digest);
  add('occupied-slot-blocks-pending-login-before-driver',
    await denied(()=>run('personal'),'agy-single-login-slot')&&calls===0&&
    (await loadProfile(root,'personal')).digest===pendingSecond.digest&&(await loadProfile(root,'work')).digest===saved.digest);
  // Independent fixture stores model the intended setup only, not two actual macOS login sessions.
  const otherRoot=join(dir,'second-fixture-store');
  const localConfig=await addPendingAgyProfile(otherRoot,'personal');
  const bind=(authenticate,signal)=>registerHarnessLogin(otherRoot,{harness:'agy',id:'personal',interactive:true,authenticate,signal});
  const prev=await bind(async()=>({status:'cancelled'}));
  const failed=await bind(async()=>({status:'auth-required'}));
  add('pending-survives-cancel-and-failure',prev.saved===false&&failed.saved===false&&
    (await loadProfile(otherRoot,'personal')).digest===localConfig.digest);
  const second=await bind(async()=>ready);
  add('pending-promotes-in-place-only-after-ready',second.saved===true&&second.profile.id==='personal'&&
    second.profile.digest!==localConfig.digest&&second.profile.identityStatus==='identity-unavailable'&&
    (await loadProfile(otherRoot,'personal')).digest===second.profile.digest&&
    (await loadProfile(root,'personal')).digest===pendingSecond.digest);
  add('cannot-recreate-or-rebind-promoted-profile',
    await denied(()=>addPendingAgyProfile(otherRoot,'personal'),'profile-already-exists')&&
    await denied(()=>bind(async()=>ready),'profile-already-exists'));
  const adapter = await verifyAgyLoginAdapter();
  if(Array.isArray(adapter)) {
    for(const row of adapter)add('adapter-'+row.id,row.pass);
  } else add('adapter-offline-contract',adapter===true || adapter?.ok===true);
  const receipt={mode:'verify-profile-login',scope:'mock login and no-prompt ACP protocol only',
    realProviderLogin:false,realAccountIdentityVerified:false,realCredentialsRead:false,checks};
  const path=join(dir,'evidence.json');
  await writeFile(path,JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
  for(const check of checks)console.log((check.pass?'PASS ':'FAIL ')+check.id);
  console.log('Evidence: '+path);
  return checks.every(c=>c.pass);
}
