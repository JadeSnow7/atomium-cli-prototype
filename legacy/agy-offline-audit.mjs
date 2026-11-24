import {createHash} from 'node:crypto';
import {spawn,execFile} from 'node:child_process';
import {createReadStream} from 'node:fs';
import {lstat,mkdir,mkdtemp,realpath,rm,writeFile} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {homedir,tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {createServer,connect} from 'node:net';
import {runIsolatedAgentWorker} from './isolated-agent-worker.mjs';

const exec=promisify(execFile);
const root=fileURLToPath(new URL('./runs',import.meta.url));
const hash=x=>createHash('sha256').update(x).digest('hex');
const policyVersion='agy-offline-initialize-v1';
const delay=n=>new Promise(resolve=>setTimeout(resolve,n));
const deferred=()=>{let resolve;const promise=new Promise(ok=>{resolve=ok;});return {resolve,promise};};
const exactPrefix='sandbox-exec: sandbox_apply: Operation not permitted';
const libraryRoots=['/System/Library','/usr/lib'];
const literal=p=>'(literal '+JSON.stringify(p)+')';
const sub=p=>'(subpath '+JSON.stringify(p)+')';
function profileFor(binary,task){
  // No network, Mach service lookup or process creation is granted. No real HOME
  // or parent working tree is allowed. System libraries are the only broad data roots.
  const readable=[literal(binary),literal('/'),literal('/dev/null'),literal('/dev/urandom'),sub(task),...libraryRoots.map(sub)];
  return [
    '(version 1)(deny default)(allow signal (target self))(allow sysctl-read)(allow ipc-posix-sem*)',
    '(allow process-exec '+literal(binary)+')',
    '(allow file-read-metadata '+readable.join(' ')+')',
    '(allow file-read-data '+readable.join(' ')+')',
    '(allow file-map-executable '+[literal(binary),...libraryRoots.map(sub)].join(' ')+')',
    '(allow file-write* '+sub(task)+' '+literal('/dev/null')+')',
  ].join('\n');
}
async function binaryDigest(binary){
  if(await realpath(binary)!==binary)throw new Error('agy-executable-not-canonical');
  const before=await lstat(binary);
  if(!before.isFile()||before.size<1||before.size>512*1024*1024||(before.mode&0o022)||(before.mode&0o100)===0)throw new Error('agy-executable-not-eligible');
  const digest=createHash('sha256');
  for await (const bytes of createReadStream(binary))digest.update(bytes);
  const after=await lstat(binary);
  if(before.ino!==after.ino||before.size!==after.size||before.mtimeMs!==after.mtimeMs)throw new Error('agy-executable-changed');
  return {sha256:digest.digest('hex'),bytes:before.size};
}
async function makeTask(parent,role){
  const path=join(parent,'task-'+role);
  await mkdir(path,{mode:0o700});
  const dirs=Object.fromEntries(['home','tmp','cwd','state','gemini'].map(name=>[name,join(path,name)]));
  await Promise.all(Object.values(dirs).map(p=>mkdir(p,{mode:0o700})));
  return {path,dirs,log:join(path,'agy.log'),role};
}
function group(pid,signal){
  if(!Number.isInteger(pid)||pid<2)return false;
  try{process.kill(-pid,signal);return true;}
  catch(e){if(e.code==='ESRCH')return false;throw e;}
}
async function bounded(p,n,value){
  let timer;
  try{return await Promise.race([p,new Promise(ok=>{timer=setTimeout(()=>ok(value),n);})]);}
  finally{clearTimeout(timer);}
}
function launch(binary,task,mark){
  const sbpl=profileFor(binary,task.path);
  const env={HOME:task.dirs.home,TMPDIR:task.dirs.tmp,PATH:'/usr/bin:/bin',LANG:'C'};
  const args=['acp','--stdio','--sandbox','--disable-telemetry','--include-default-customizations=false',
    '--app-data-dir',task.dirs.state,'--gemini-dir',task.dirs.gemini,'--log-file',task.log];
  const child=spawn('/usr/bin/sandbox-exec',['-p',sbpl,binary,...args],{
    cwd:task.dirs.cwd,env,detached:true,stdio:['pipe','pipe','pipe'],
  });
  const closed=deferred(),initialized=deferred();
  let closeSeen=false,finalExit=null,stdout=Buffer.alloc(0),rawBytes=0,diagnostic='',settled=false,firmFailure=false;
  const resolve=value=>{if(!settled){settled=true;initialized.resolve(value);}};
  const reject=reason=>{firmFailure=true;resolve({status:reason});};
  child.once('error',()=>reject('launch-error'));
  child.stdin.on('error',()=>reject('stdio-error'));
  child.stdout.on('data',part=>{
    rawBytes+=part.length;
    if(rawBytes>131072){reject('wire-limit');return;}
    stdout=Buffer.concat([stdout,part]);
    for(let i;(i=stdout.indexOf(10))>=0;){
      const line=stdout.subarray(0,i);stdout=stdout.subarray(i+1);
      try{
        if(settled||line.length>65536)throw new Error();
        const m=JSON.parse(line.toString('utf8'));
        const version=m?.result?.agentInfo?.version;
        if(m?.jsonrpc!=='2.0'||m.id!==1||m.result?.protocolVersion!==1||
           m.result?.agentInfo?.name!=='Antigravity ACP Server'||
           typeof version!=='string'||!/^\d+\.\d+\.\d{1,4}$/.test(version))throw new Error();
        mark('initialize-confirmed',task.role);
        resolve({status:'initialized',protocolVersion:1,version,observedAuthMethodCount:Array.isArray(m.result.authMethods)?m.result.authMethods.length:0});
      }catch{reject('initialize-rejected');}
    }
  });
  child.stderr.on('data',part=>{if(diagnostic.length<1024)diagnostic+=part.toString('utf8',0,1024-diagnostic.length);});
  child.once('exit',(code,signal)=>{finalExit={code,signal};});
  child.once('close',()=>{
    closeSeen=true;
    closed.resolve();
    if(!settled)resolve({status:diagnostic.includes(exactPrefix)?'launcher-blocked':'exit-before-initialize'});
  });
  if(Number.isInteger(child.pid)){
    mark('process-started',task.role);
    // Deliberately never send session/new, authenticate, prompt, or any other request.
    child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',
      params:{protocolVersion:1,clientCapabilities:{fs:{readTextFile:false,writeTextFile:false},terminal:false,auth:{terminal:false}},clientInfo:{name:'atomium',version:'0.1.0'}}})+'\n');
    mark('initialize-sent',task.role);
  }
  const alive=()=>!closeSeen&&child.exitCode===null&&child.signalCode===null&&group(child.pid,0);
  let stopping=null;
  const stop=()=>stopping??= (async ()=>{
    const requested=group(child.pid,'SIGTERM');
    const graceful=await bounded(closed.promise.then(()=>true),450,false);
    let forced=false;
    if(!graceful||group(child.pid,0))forced=group(child.pid,'SIGKILL');
    child.stdin.destroy();
    await bounded(closed.promise,650,null);
    for(let i=0;i<8&&group(child.pid,0);i++)await delay(25);
    return {requested,forced,reaped:closeSeen,exit:finalExit,groupGone:!group(child.pid,0),scope:'this fixed process group only'};
  })();
  return {pid:child.pid,initialized:initialized.promise,alive,stop,wireOk:()=>!firmFailure,profileDigest:hash(sbpl)};
}
async function pathEvidence(task){
  const dirs={};
  for(const [name,path] of Object.entries({...task.dirs,task:task.path})){
    const st=await lstat(path);
    dirs[name]={sameOwner:st.uid===process.getuid(),private:st.isDirectory()&&!(st.mode&0o077),canonical:await realpath(path)===path,
      containsEntries:await import('node:fs/promises').then(fs=>fs.readdir(path)).then(names=>names.length>0)};
  }
  let log={observed:false};
  try{
    const st=await lstat(task.log);
    log={observed:st.isFile()&&await realpath(task.log)===task.log,sameOwner:st.uid===process.getuid(),nonempty:st.size>0};
  }catch(e){if(e.code!=='ENOENT')throw e;}
  return {directories:dirs,configuredLog:log};
}
async function controlRun(base,signal){
  const taskDir=join(base,'offline-control');
  await mkdir(taskDir,{mode:0o700});
  const host=join(base,'fixed-host-canary'),peer=join(base,'fixed-peer-canary');
  await Promise.all([host,peer].map(path=>writeFile(path,'SYNTHETIC_ONLY',{mode:0o600,flag:'wx'})));
  let connections=0;
  const server=createServer(sock=>{connections++;sock.end();});
  try{
    await new Promise((yes,no)=>{server.once('error',no);server.listen(0,'127.0.0.1',yes);});
    const port=server.address().port;
    await new Promise((yes,no)=>{const sock=connect({host:'127.0.0.1',port});sock.once('error',no);sock.once('end',yes);});
    const before=connections;
    const result=await runIsolatedAgentWorker({taskDir,scenario:'no-request',loopbackPort:port,outsideCanaryPath:host,
      peerCanaryPath:peer,jobId:'f'.repeat(24),signal,timeoutMs:2200});
    return {...result,controlConnections:before,workerConnections:connections-before,
      pass:result.status==='completed'&&Object.values(result.checks??{}).length===5&&Object.values(result.checks).every(Boolean)&&before===1&&connections===before};
  }finally{if(server.listening)await new Promise(ok=>server.close(ok));}
}
export async function verifyAgyOffline({signal}={}){
  if(process.platform!=='darwin')throw new Error('macOS-required');
  await mkdir(root,{mode:0o700,recursive:true});
  if(await realpath(root)!==root||!(await lstat(root)).isDirectory())throw new Error('unsafe-run-root');
  const dir=await mkdtemp(join(root,'agy-offline-'));
  const base=await realpath(await mkdtemp(join(tmpdir(),'atomium-agy-offline-')));
  let A,B,stopA,stopB,binaryInfo,control,paths,status='failed',phase='prepare',initialized=null,checks=[],disposed=false;
  const events=[],mark=(event,role)=>events.push({sequence:events.length+1,event,role});
  const aborted=deferred(),abort=()=>aborted.resolve('cancelled');
  signal?.addEventListener('abort',abort,{once:true});
  if(signal?.aborted)abort();
  try{
    // Only a trusted non-vendor process is used to confirm this launcher is available.
    const probe='(version 1)(deny default)(allow sysctl-read)(allow file-read-metadata)(allow process-exec (literal "/usr/bin/true"))(allow file-read-data (literal "/") (literal "/usr/bin/true") (subpath "/usr/lib") (subpath "/System/Library"))(allow file-map-executable (literal "/usr/bin/true") (subpath "/usr/lib") (subpath "/System/Library"))';
    phase='launcher-preflight';
    try{await exec('/usr/bin/sandbox-exec',['-p',probe,'/usr/bin/true'],{timeout:1500,env:{PATH:'/usr/bin:/bin',LANG:'C'},cwd:base});}
    catch(e){if(String(e.stderr??'').includes(exactPrefix)){phase='launcher-blocked';status='blocked';}else throw e;}
    if(status!=='blocked'){
      phase='synthetic-control';
      control=await controlRun(base,signal);
      if(control.reason==='launcher-blocked'){phase='launcher-blocked';status='blocked';}
      if(!control.pass&&status!=='blocked')throw new Error('synthetic-offline-control-unverified');
    }
    if(status!=='blocked'&&!signal?.aborted){
      phase='initialize';
      const binary=join(homedir(),'.local','bin','agy');
      binaryInfo=await binaryDigest(binary);
      const taskA=await makeTask(base,'A'),taskB=await makeTask(base,'B');
      A=launch(binary,taskA,mark);B=launch(binary,taskB,mark);
      const responses=await bounded(Promise.race([Promise.all([A.initialized,B.initialized]),aborted.promise]),4500,'timed-out');
      if(!Array.isArray(responses)){phase=responses;}
      else{
        const [left,right]=responses;initialized={A:left,B:right};
        if(responses.some(r=>r.status==='launcher-blocked')){phase='launcher-blocked';status='blocked';}
        else if(responses.every(r=>r.status==='initialized')&&A.alive()&&B.alive()){
          mark('both-initialized-and-live');
          phase='cancellation';
          mark('cancel-requested','A');stopA=await A.stop();mark('stop-observed','A');
          const survives=B.alive();if(survives)mark('peer-still-live','B');
          stopB=await B.stop();mark('stop-observed','B');
          paths={A:await pathEvidence(taskA),B:await pathEvidence(taskB)};
          const scopes=Object.values(paths).every(e=>Object.values(e.directories).every(x=>x.sameOwner&&x.private&&x.canonical));
          const sameBinary=(await binaryDigest(binary)).sha256===binaryInfo.sha256;
          checks=[
            ['fixed-macos-launcher-and-offline-synthetic-control',control.pass],
            ['two-processes-of-one-installed-binary-parallel-acp-v1',Number.isInteger(A.pid)&&Number.isInteger(B.pid)&&A.pid!==B.pid&&left.version===right.version&&A.wireOk()&&B.wireOk()],
            ['fresh-disjoint-private-task-directories',scopes],
            ['configured-task-log-observed-for-both',paths.A.configuredLog.observed&&paths.B.configuredLog.observed&&paths.A.configuredLog.sameOwner&&paths.B.configuredLog.sameOwner],
            ['cancel-A-reap-and-B-remains-live',stopA.requested&&stopA.reaped&&stopA.groupGone&&survives],
            ['both-fixed-process-groups-reaped',stopA.reaped&&stopA.groupGone&&stopB.reaped&&stopB.groupGone],
            ['installed-executable-binding-unchanged',sameBinary],
          ].map(([id,pass])=>({id,pass:Boolean(pass)}));
          status=checks.every(r=>r.pass)?'passed':'failed';phase='completed';
        }else{phase='initialize-unverified';}
      }
    }else if(signal?.aborted){phase='cancelled';}
  }catch(e){
    if(phase==='synthetic-control'&&['EPERM','EACCES'].includes(e.code)){phase='listener-blocked';status='blocked';}
    else if(signal?.aborted){phase='cancelled';}
  }finally{
    signal?.removeEventListener('abort',abort);
    if(A)stopA??=await A.stop();
    if(B)stopB??=await B.stop();
    try{await rm(base,{recursive:true,force:true});disposed=true;}catch{}
    if(signal?.aborted){status='cancelled';phase='cancelled';}
    if(!disposed||stopA?.groupGone===false||stopB?.groupGone===false)status='failed';
  }
  const receipt={version:1,policyVersion,mode:'verify-agy-offline',status,phase,checks,installedBinary:binaryInfo??null,
    workers:{A:{pid:A?.pid??null,policySha256:A?.profileDigest??null,initialize:initialized?.A??null,cleanup:stopA??null,paths:paths?.A??null},
      B:{pid:B?.pid??null,policySha256:B?.profileDigest??null,initialize:initialized?.B??null,cleanup:stopB??null,paths:paths?.B??null}},
    syntheticControl:control??null,events,disposed,onlyAcpMethod:'initialize',providerPrompts:0,loginInvoked:false,
    contract:{network:'deny-default configuration and separate synthetic loopback control',mach:'no service lookup granted; Atomium did not read, export or inject credentials; vendor Keychain behavior was not traced',
      configuredAgyPaths:['HOME','TMPDIR','cwd','--app-data-dir','--gemini-dir','--log-file'],
      vendorPathObservation:'Configured paths are not proven state namespaces. Only directory ownership/mode and actual log creation observed.'},
    notCovered:['real account separation or login','Keychain calls/behavior','authenticated ACP session or model','provider egress','arbitrary project code or escaped process groups']};
  const evidencePath=join(dir,'evidence.json');
  await writeFile(evidencePath,JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
  for(const c of checks)console.log((c.pass?'PASS ':'FAIL ')+c.id);
  console.log((status==='passed'?'PASS ':status==='blocked'?'BLOCKED ':'FAIL ')+phase);
  console.log('Evidence: '+evidencePath);
  return {...receipt,evidencePath};
}
