import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { addHarnessConfig, loadProfile, registerHarnessLogin } from './agent-profiles.mjs';
import { patchPrompt, proposeView } from './proposal-contract.mjs';
import { namedAgyProposal } from './agy-acp.mjs';

const runs=fileURLToPath(new URL('./runs',import.meta.url));
const operation='synthetic-proposal';
const timeoutMs=75000;
const allowedStops=new Set(['auth-required','protocol-timeout','response-rejected','cancelled','rpc-error','process-start-error',
  'process-ended','protocol-error','profile-state-unavailable','profile-policy-unavailable','credit-fallback-unverified',
  'credits-policy-blocked','billing-mode-unverified','provider-quota-or-rate-limit','provider-unavailable','provider-policy-rejected',
  'dedicated-policy-unavailable','provider-proposal-unavailable','proposal-cleanup-incomplete','invalid-agy-timeout','invalid-fixed-proposal']);
async function fixtureDirectory(prefix){
  await mkdir(runs,{mode:0o700,recursive:true});
  if(!(await lstat(runs)).isDirectory()||await realpath(runs)!==runs)throw new Error('unsafe-run-root');
  return mkdtemp(join(runs,prefix));
}
async function save(dir,record){
  const evidencePath=join(dir,'evidence.json');
  await writeFile(evidencePath,JSON.stringify(record,null,2)+'\n',{mode:0o600,flag:'wx'});
  return {...record,evidencePath};
}
const count=value=>Number.isInteger(value)&&value>=0&&value<=10000?value:null;
const asCode=stage=>{
  if(stage?.rpcCode===429)return 'provider-quota-or-rate-limit';
  return allowedStops.has(stage?.status)?stage.status:'provider-unavailable-or-unexpected';
};
async function dispatch(root,{harness,profile,signal,includedPlanConfirmed=false},adapter, simulated){
  if(harness!=='agy'&&harness!=='codex')throw new Error('unsupported-task-harness');
  const config=await loadProfile(root,profile);
  if(config.agent!==harness)throw new Error('harness-profile-mismatch');
  if(harness!=='agy'||config.schema!=='atomium-agy-login-profile-v1'||config.credentialRef!=='agy:os-keyring-single-slot')
    throw new Error('named-agy-login-profile-required');
  const dir=await fixtureDirectory(simulated?'named-proposal-fixture-':'named-proposal-');
  let stage=null,proposal=null,status=signal?.aborted?'cancelled':'billing-mode-unverified',adapterCalled=false;
  if(!signal?.aborted&&includedPlanConfirmed===true){
    adapterCalled=true;
    try{stage=await adapter(join(root,'.agy-host-state'),patchPrompt,{timeoutMs,signal,includedPlanConfirmed});}
    catch{}
    if(signal?.aborted)status='cancelled';
    else if(stage?.status==='response-ready'&&stage.promptSent===true&&stage.permissionsDenied===0&&stage.otherCallsDenied===0&&
          stage.toolUpdates===0&&stage.creditFallback==='off-by-documented-default'){
      proposal=await proposeView(async()=>stage.text,'agy-acp-host');
      status=proposal.status;
    }else status=stage?.status==='response-ready'?'provider-policy-rejected':asCode(stage);
  }
  const stoppedBeforeDispatch=stage?.promptSent===false||!adapterCalled;
  return save(dir,{schema:1,operation,mode:simulated?'fixture':'host-provider',
    selection:{harness,profileId:config.id,profileDigest:config.digest,timeoutMs},status,
    taskWorkspace:'empty-fixture',sandboxVerified:false,identityVerified:false,scope:'one fixed proposal; no project modification or export',
    provider:{adapterInvoked:adapterCalled,billingModeUserAsserted:includedPlanConfirmed===true,billingModeIndependentlyVerified:false,
      promptSent:stage?.promptSent===true?true:stoppedBeforeDispatch?false:null,
      protocolVersion:stage?.protocolVersion===1?1:null,
      permissionsDenied:count(stage?.permissionsDenied),otherCallsDenied:count(stage?.otherCallsDenied),toolUpdates:count(stage?.toolUpdates),
      creditFallback:stage?.creditFallback==='off-by-documented-default'?'off-by-documented-default':'not-confirmed'},
    proposal:status==='accepted'?{patch:proposal.patch,patchSha256:proposal.patchSha256}:null,applied:false,exported:false});
}
export async function runNamedProposal(root,options){
  return dispatch(root,options,namedAgyProposal,false);
}

export async function verifyNamedProposal(){
  const dir=await fixtureDirectory('named-proposal-audit-'),root=join(dir,'profiles');
  const ids={login:'work',config:'agy-local',other:'codex-local'};
  await registerHarnessLogin(root,{id:ids.login,harness:'agy',interactive:true,
    authenticate:async()=>({status:'ready',sessionReady:true,identityStatus:'identity-unavailable',promptSent:false})});
  await Promise.all([addHarnessConfig(root,{id:ids.config,harness:'agy'}),addHarnessConfig(root,{id:ids.other,harness:'codex'})]);
  const checks=[], receipts=[];
  let invocations=0;
  const add=(id,pass)=>checks.push({id,pass:Boolean(pass)});
  const ready={status:'response-ready',protocolVersion:1,promptSent:true,permissionsDenied:0,otherCallsDenied:0,toolUpdates:0,
    creditFallback:'off-by-documented-default',text:'{"view":"completed"}'};
  const invoke=(stage,options={})=>dispatch(root,{harness:'agy',profile:ids.login,includedPlanConfirmed:true,...options},async (state,prompt,config)=>{
    invocations++;
    if(state!==join(root,'.agy-host-state')||prompt!==patchPrompt||config.timeoutMs!==timeoutMs||config.includedPlanConfirmed!==true)throw new Error('fixture-selection-changed');
    return stage;
  },true);
  const reject=async (options,why)=>{try{await invoke(ready,options);return false;}catch(e){return e.message===why;}};
  add('only-registered-agy-profile-dispatches',
    await reject({profile:ids.config},'named-agy-login-profile-required') &&
    await reject({harness:'codex',profile:ids.other},'named-agy-login-profile-required') &&
    await reject({harness:'codex',profile:ids.login},'harness-profile-mismatch') &&
    await reject({profile:'missing'},'profile-not-found') && invocations===0);
  const check=async (id,stage,expected,options={})=>{
    const before=invocations,r=await invoke(stage,options);
    receipts.push(r.evidencePath);
    const shouldDispatch=!options.signal?.aborted&&options.includedPlanConfirmed!==false;
    add(id,r.status===expected&&invocations-before===(shouldDispatch?1:0)&&r.provider.adapterInvoked===shouldDispatch&&r.applied===false&&r.exported===false&&
      (expected==='accepted'?r.proposal?.patch?.value==='completed':r.proposal===null)&&
      !JSON.stringify(r).includes('RAW_TEST_SECRET')&&r.selection.profileDigest===(await loadProfile(root,ids.login)).digest);
  };
  await check('one-bound-proposal-accepted',ready,'accepted');
  await check('schema-rejected-and-raw-response-omitted',{...ready,text:'RAW_TEST_SECRET'},'proposal-schema-rejected');
  await check('valid-shape-wrong-change-rejected',{...ready,text:'{"view":"all"}'},'proposal-contract-rejected');
  await check('no-tool-side-effect-path',{...ready,toolUpdates:1},'provider-policy-rejected');
  await check('credit-default-must-be-confirmed',{...ready,creditFallback:null},'provider-policy-rejected');
  await check('auth-rejection-no-fallback',{status:'auth-required',promptSent:false},'auth-required');
  await check('explicit-quota-rejection-no-retry',{status:'rpc-error',rpcCode:429,promptSent:true},'provider-quota-or-rate-limit');
  await check('cancel-before-dispatch',ready,'cancelled',{signal:AbortSignal.abort()});
  await check('billing-uncertainty-blocks-before-adapter',ready,'billing-mode-unverified',{includedPlanConfirmed:false});
  const state=join(root,'.agy-host-state'); // deliberately nonexistent, no vendor account or provider launch
  add('live-adapter-included-plan-gate-and-fixed-prompt',
    (await namedAgyProposal(state,patchPrompt,{timeoutMs})).status==='billing-mode-unverified'&&
    (await namedAgyProposal(state,'wrong', {timeoutMs,includedPlanConfirmed:true})).status==='invalid-fixed-proposal'&&
    (await namedAgyProposal(state,patchPrompt,{timeoutMs,includedPlanConfirmed:true})).status==='dedicated-policy-unavailable');
  const report=await save(dir,{schema:1,scope:'synthetic dispatch adapter; no real provider invocation',checks,receipts,
    status:checks.every(c=>c.pass)?'passed':'failed'});
  for(const check of checks)console.log((check.pass?'PASS ':'FAIL ')+check.id);
  console.log('Evidence: '+report.evidencePath);
  return report;
}
