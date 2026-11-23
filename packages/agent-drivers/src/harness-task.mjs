import { execFile } from 'node:child_process';
import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { loadProfile, addHarnessConfig } from './agent-profiles.mjs';

const runs=fileURLToPath(new URL('./runs',import.meta.url));
const execute=promisify(execFile);
const drivers=Object.freeze({
  agy:Object.freeze({path:join(homedir(),'.local','bin','agy'),version:/^(\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i}),
  codex:Object.freeze({path:'/opt/homebrew/bin/codex',version:/^codex-cli (\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i}),
});
const known=h=>typeof h==='string'&&Object.hasOwn(drivers,h);
const sha=/^[a-f0-9]{64}$/;
const exitReason=e=>e?.code==='ENOENT'?'harness-not-installed':e?.killed?'harness-timed-out':'harness-launch-failed';
async function fresh(prefix){
  await mkdir(runs,{recursive:true,mode:0o700});
  if(!(await lstat(runs)).isDirectory()||await realpath(runs)!==runs)throw new Error('unsafe-run-root');
  return mkdtemp(join(runs,prefix));
}
async function record(dir,report){
  const evidencePath=join(dir,'evidence.json');
  await writeFile(evidencePath,JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
  return {...report,evidencePath};
}
export async function runHarnessTask(root,{harness,profile,operation='version-check'}){
  if(!known(harness))throw new Error('unsupported-task-harness');
  if(operation!=='version-check')throw new Error('unsupported-task-operation');
  const config=await loadProfile(root,profile);
  if(config.agent!==harness)throw new Error('harness-profile-mismatch');
  const timeoutMs=config.timeoutMs??4000;  // compatibility for the existing host login Profile
  if(!sha.test(config.digest)||!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>15000)
    throw new Error('invalid-task-profile');
  const task=await fresh('harness-task-');
  const dirs=Object.fromEntries(['cwd','home','tmp'].map(k=>[k,join(task,k)]));
  await Promise.all(Object.values(dirs).map(p=>mkdir(p,{mode:0o700})));
  const driver=drivers[harness], planned={harness,profile:config.id,profileDigest:config.digest,operation,timeoutMs};
  let pid=null,version=null,reason=null;
  try{
    const processResult=execute(driver.path,['--version'],{cwd:dirs.cwd,timeout:timeoutMs,killSignal:'SIGKILL',maxBuffer:2048,
      env:{HOME:dirs.home,TMPDIR:dirs.tmp,PATH:'/usr/bin:/bin',LANG:'C'}});
    pid=processResult.child.pid??null;
    const {stdout}=await processResult;
    version=driver.version.exec(stdout.trim())?.[1]??null;
    if(version===null)reason='unexpected-version-output';
  }catch(e){reason=exitReason(e);}
  return record(task,{schema:1,scope:'fixed local executable version check; no authenticated task or isolation claim',
    status:reason?'failed':'passed',reason,selection:planned,pid,version,sandboxVerified:false,
    loginRequested:false,projectLoaded:false,modelPromptSent:false,
    taskDirs:{cwd:'cwd',home:'home',temp:'tmp',freshPrivate:true}});
}

export async function verifyHarnessTasks(){
  const dir=await fresh('harness-config-audit-'), root=join(dir,'fixture-store');
  const checks=[];
  const add=(id,pass)=>checks.push({id,pass:Boolean(pass)});
  const ids={agy:'agy-a',codex:'codex-b',second:'agy-second'};
  const selected=await Promise.all([
    addHarnessConfig(root,{harness:'agy',id:ids.agy,timeoutMs:3100}),
    addHarnessConfig(root,{harness:'codex',id:ids.codex,timeoutMs:6200}),
    addHarnessConfig(root,{harness:'agy',id:ids.second,timeoutMs:8700}),
  ]);
  const reload=await Promise.all(Object.values(ids).map(id=>loadProfile(root,id)));
  add('three-configs-persist-with-distinct-digests',new Set(reload.map(row=>row.digest)).size===3 &&
    reload.every((row,i)=>row.digest===selected[i].digest&&Object.isFrozen(row)));
  const reject=async (harness,profile,operation,expected)=>{
    try{await runHarnessTask(root,{harness,profile,operation});return false;}
    catch(e){return e.message===expected;}
  };
  add('wrong-harness-profile-and-operation-stop-before-launch',
    await reject('codex',ids.agy,'version-check','harness-profile-mismatch') &&
    await reject('agy','missing','version-check','profile-not-found') &&
    await reject('agy',ids.agy,'arbitrary','unsupported-task-operation'));
  const tasks=await Promise.all([
    runHarnessTask(root,{harness:'agy',profile:ids.second}),
    runHarnessTask(root,{harness:'codex',profile:ids.codex}),
  ]);
  add('selected-driver-and-timeout-applied',tasks.every(row=>row.status==='passed') &&
    tasks[0].selection.profile===ids.second&&tasks[0].selection.profileDigest===reload[2].digest&&tasks[0].selection.timeoutMs===8700&&
    tasks[1].selection.profile===ids.codex&&tasks[1].selection.profileDigest===reload[1].digest&&tasks[1].selection.timeoutMs===6200);
  add('distinct-actual-child-processes-and-no-model-dispatch',tasks.every(row=>Number.isInteger(row.pid)&&
    row.taskDirs.freshPrivate&&row.modelPromptSent===false&&row.loginRequested===false)&&tasks[0].pid!==tasks[1].pid);
  const report=await record(dir,{schema:1,mode:'verify-harness-config',checks,
    status:checks.every(c=>c.pass)?'passed':'failed',tasks:tasks.map(({evidencePath,selection,version,status})=>({evidencePath,selection,version,status})),
    liveProviderLogin:false,modelPromptSent:false});
  for(const check of checks)console.log((check.pass?'PASS ':'FAIL ')+check.id);
  console.log('Evidence: '+report.evidencePath);
  return report;
}
