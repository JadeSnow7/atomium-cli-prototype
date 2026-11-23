import {spawn} from 'node:child_process';
import {createServer, connect} from 'node:net';
import {mkdir,mkdtemp,lstat,realpath,writeFile} from 'node:fs/promises';
import {dirname,join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';

const route='fixture-model';
const inputs=Object.freeze({clean:'Summarize synthetic item A.',canary:'Synthetic marker ATOMIUM_DLP_CANARY_V1','unsupported-route':'Summarize synthetic item A.','cross-binding':'Summarize synthetic item B.'});
const scenarios=new Set([...Object.keys(inputs),'no-request','hang']);
const reasons=new Set(['approved','policy','synthetic-marker','canary','route','revoked','rate-limit','timeout','provider-error','blocked','unknown']);
const mismatchText='Unapproved synthetic B binding claim.';
const fields=['taskReadWrite','networkDenied','hostReadDenied','peerReadDenied','cleanEnvironment'];
const MAX_LINE=4096, MAX_TOTAL=16384;
const literal=p=>'(literal '+JSON.stringify(p)+')';
const sub=p=>'(subpath '+JSON.stringify(p)+')';
const safeChildCode=[
  "import {writeFile,readFile,open} from 'node:fs/promises';",
  "import {connect} from 'node:net';",
  "import {createInterface} from 'node:readline';",
  "const [jobId,scenario,port,host,peer,foreignJobId]=process.argv.slice(2);",
  "const prompt="+JSON.stringify(inputs)+";",
  "const mismatchText="+JSON.stringify(mismatchText)+";",
  "const out=o=>process.stdout.write(JSON.stringify({jobId,...o})+'\\n');",
  "const good=e=>['EACCES','EPERM'].includes(e.code);",
  "const readDenied=async file=>{try{const h=await open(file,'r');await h.close();return false;}catch(e){return good(e);}};",
  "const networkDenied=await new Promise(yes=>{const s=connect({host:'127.0.0.1',port:Number(port)});s.once('connect',()=>{s.destroy();yes(false)});s.once('error',e=>yes(good(e)));s.setTimeout(1000,()=>{s.destroy();yes(false)});});",
  "let taskReadWrite=false;",
  "try{await writeFile('task-proof','SYNTHETIC_CONTROL',{flag:'wx',mode:0o600});taskReadWrite=(await readFile('task-proof','utf8'))==='SYNTHETIC_CONTROL';}catch{}",
  "const checks={taskReadWrite,networkDenied,hostReadDenied:await readDenied(host),peerReadDenied:await readDenied(peer),cleanEnvironment:Object.keys(process.env).sort().join(',')==='HOME,LANG,OPENSSL_CONF,PATH,TMPDIR'&&!process.env.ATOMIUM_WORKER_FAKE_KEY};",
  "out({type:'boundary-report',checks});",
  "if(Object.values(checks).includes(false)){out({type:'complete',status:'failed'});}",
  "else if(scenario==='no-request'){out({type:'complete',status:'completed'});}",
  "else if(scenario==='hang'){setInterval(()=>{},1000);}",
  "else {",
  "  const ui=createInterface({input:process.stdin});",
  "  async function request(packet){",
  "    const answer=new Promise(yes=>{ui.once('line',yes);ui.once('close',()=>yes(''));});",
  "    out(packet);",
  "    try{return JSON.parse(await answer);}catch{return null;}",
  "  }",
  "  let valid=true;",
  "  if(scenario==='cross-binding'){",
  "    const denied=await request({type:'model-request',jobId:foreignJobId,route:'fixture-model',text:mismatchText});",
  "    valid=denied?.type==='model-result'&&denied.jobId===jobId&&denied.decision==='block';",
  "  }",
  "  const ack=valid?await request({type:'model-request',route:scenario==='unsupported-route'?'fixture-denied':'fixture-model',text:prompt[scenario]}):null;",
  "  ui.close();process.stdin.pause();",
  "  const status=ack?.type==='model-result'&&ack.jobId===jobId?(ack.decision==='allow'?'completed':ack.decision==='block'?'blocked':'failed'):'failed';",
  "  out({type:'complete',status});",
  "}",
].join('\n');

function policy(task,runtime) {
  return [
    '(version 1)(deny default)(allow process-fork)(allow signal (target self))(allow ipc-posix-sem*)(allow sysctl-read)(allow file-read-metadata)',
    '(allow process-exec '+literal(runtime)+')',
    '(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.notification_center"))',
    '(allow file-read-data '+[task,'/usr/lib','/System/Library','/Library/Apple/System/Library','/usr/share/icu','/private/var/db/timezone'].map(sub).join(' ')+' '+['/',runtime,'/dev/null','/dev/urandom'].map(literal).join(' ')+String.raw` (regex #"^/opt/homebrew/Cellar/[^/]+/[^/]+/lib/.*[.]dylib$") (regex #"^/opt/homebrew/opt/[^/]+/lib/.*[.]dylib$"))`,
    '(allow file-map-executable '+['/usr/lib','/System/Library','/Library/Apple/System/Library','/opt/homebrew/Cellar','/opt/homebrew/opt'].map(sub).join(' ')+' '+literal(runtime)+')',
    '(allow file-write* '+sub(task)+' '+literal('/dev/null')+')',
  ].join('\n');
}
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
function parse(line) {
  if(line.length<2||line.length>MAX_LINE)throw new Error('worker-wire-line-limit');
  const text=line.toString('utf8');
  if(text.includes('\ufffd'))throw new Error('worker-wire-invalid-utf8');
  const packet=JSON.parse(text);
  // Trusted fixture uses canonical JSON.stringify. Canonical comparison rejects duplicate
  // keys and ambiguous input without giving the worker extra interpretation rules.
  if(JSON.stringify(packet)!==text||typeof packet?.jobId!=='string')throw new Error('worker-wire-identity');
  return packet;
}
const bindingProbe=(msg,{scenario,phase,bindingDenied,foreignJobId})=>scenario==='cross-binding'&&phase==='request'&&bindingDenied===0&&
  msg.jobId===foreignJobId&&msg.type==='model-request'&&msg.route===route&&msg.text===mismatchText&&exact(msg,['type','route','jobId','text']);
export function verifyWorkerProtocolFixture() {
  const own='a'.repeat(24),foreign='b'.repeat(24);
  const ctx={scenario:'cross-binding',phase:'request',bindingDenied:0,foreignJobId:foreign};
  const row={type:'model-request',route,jobId:foreign,text:mismatchText};
  let duplicateRejected=false,oversizeRejected=false;
  try{parse(Buffer.from('{"jobId":"'+own+'","jobId":"'+own+'"}'));}catch{duplicateRejected=true;}
  try{parse(Buffer.alloc(MAX_LINE+1));}catch{oversizeRejected=true;}
  return [
    {id:'closed-wire-binding-negative-recognized',pass:bindingProbe(parse(Buffer.from(JSON.stringify(row))),ctx)},
    {id:'ordinary-worker-has-no-binding-exception',pass:!bindingProbe(row,{...ctx,scenario:'clean'})},
    {id:'duplicate-binding-probe-rejected',pass:!bindingProbe(row,{...ctx,bindingDenied:1})},
    {id:'out-of-phase-and-altered-binding-rejected',pass:!bindingProbe(row,{...ctx,phase:'waiting'})&&!bindingProbe({...row,text:'altered'},ctx)},
    {id:'ambiguous-and-oversize-wire-rejected',pass:duplicateRejected&&oversizeRejected},
  ];
}
function killGroup(pid,signal) {
  if(!Number.isInteger(pid)||pid<2)return false;
  try{process.kill(-pid,signal);return true;}
  catch(e){if(e.code==='ESRCH')return false;throw e;}
}
const delay=n=>new Promise(yes=>setTimeout(yes,n));
async function boundedClose(child,closed) {
  const pid=child.pid;
  let forced=killGroup(pid,'SIGTERM');
  const finished=await Promise.race([closed.then(()=>true),delay(350).then(()=>false)]);
  if(!finished||killGroup(pid,0)){forced=killGroup(pid,'SIGKILL')||forced;}
  await Promise.race([closed,delay(650)]);
  for(let i=0;i<10&&killGroup(pid,0);i++)await delay(25);
  const groupGone=!killGroup(pid,0);
  return {groupGone,forced,scope:'fixed process group; no escaped sessions claim'};
}
async function launch({task,scenario,invoke,port,host,peer,jobId,foreignJobId,onForeignBindingDenied,signal,timeoutMs}) {
  const home=join(task,'home'),tmp=join(task,'tmp'),source=join(task,'worker.mjs'),openssl=join(task,'openssl.cnf');
  await Promise.all([mkdir(home,{mode:0o700}),mkdir(tmp,{mode:0o700}),writeFile(source,safeChildCode,{mode:0o400,flag:'wx'}),writeFile(openssl,'# no host OpenSSL options\n',{mode:0o400,flag:'wx'})]);
  const runtime=await realpath(process.execPath);
  const child=spawn('/usr/bin/sandbox-exec',['-p',policy(task,runtime),runtime,source,jobId,scenario,String(port),host,peer,foreignJobId??''],{
    cwd:task,env:{HOME:home,TMPDIR:tmp,PATH:'/usr/bin:/bin',LANG:'C',OPENSSL_CONF:openssl},stdio:['pipe','pipe','pipe'],detached:true,
  });
  let resultResolve;
  const done=new Promise(yes=>{resultResolve=yes;});
  let closedResolve;
  const closed=new Promise(yes=>{closedResolve=yes;});
  let phase='boundary',pending=Buffer.alloc(0),total=0,checks=null,requestCount=0,bindingDenied=0,decision=null,callbackReason=null,completed=null,ending=false;
  const callbackAbort=new AbortController();
  const stop=status=>{if(!ending){ending=true;callbackAbort.abort();resultResolve(status);}};
  const aborted=()=>stop('aborted');
  const timer=setTimeout(()=>stop('timed-out'),timeoutMs);
  signal?.addEventListener('abort',aborted,{once:true});
  if(signal?.aborted)aborted();
  function result(dec,reason) {
    if(ending)return;
    decision=dec;
    callbackReason=reasons.has(reason)?reason:null;
    phase='complete';
    child.stdin.end(JSON.stringify({type:'model-result',jobId,decision})+'\n');
  }
  function processLine(line){
    const msg=parse(line);
    if(msg.jobId!==jobId){
      if(!bindingProbe(msg,{scenario,phase,bindingDenied,foreignJobId}))throw new Error('worker-wire-identity');
      requestCount++;
      bindingDenied++;
      phase='waiting-binding-denial';
      const claimed=Object.freeze({type:'model-request',route,jobId:foreignJobId,text:mismatchText});
      Promise.resolve().then(()=>onForeignBindingDenied(claimed,{signal:callbackAbort.signal})).then(()=>{
        if(ending)return;
        phase='request';
        child.stdin.write(JSON.stringify({type:'model-result',jobId,decision:'block'})+'\n');
      },()=>stop('binding-barrier-failed'));
      return;
    }
    if(phase==='boundary'&&msg.type==='boundary-report'&&exact(msg,['type','jobId','checks'])&&exact(msg.checks,fields)&&fields.every(k=>typeof msg.checks[k]==='boolean')){
      checks=msg.checks;phase=Object.values(checks).every(Boolean)?(scenario==='no-request'||scenario==='hang'?'complete':'request'):'incomplete';return;
    }
    if(phase==='request'&&msg.type==='model-request'&&exact(msg,['type','route','jobId','text'])&&msg.text===inputs[scenario]){
      if(scenario==='cross-binding'&&bindingDenied!==1)throw new Error('worker-binding-probe-not-observed');
      requestCount++;
      if(msg.route!==route){
        if(scenario!=='unsupported-route'||msg.route!=='fixture-denied')throw new Error('worker-route-invalid');
        result('block','route');return;
      }
      if(scenario==='unsupported-route')throw new Error('worker-scenario-invalid');
      phase='waiting';
      Promise.resolve().then(()=>{
        if(callbackAbort.signal.aborted)return {decision:'block',reason:'timeout'};
        return invoke(Object.freeze({type:'model-request',route,jobId,text:msg.text}),{signal:callbackAbort.signal});
      }).then(value=>{
        if(ending)return;
        if(!value||!['allow','block'].includes(value.decision))return result('block','policy');
        result(value.decision,value.reason);
      },()=>result('block','provider-error'));
      return;
    }
    if((phase==='complete'||phase==='incomplete')&&msg.type==='complete'&&exact(msg,['type','jobId','status'])){
      const expected=phase==='incomplete'?'failed':decision==='block'?'blocked':'completed';
      if(msg.status!==expected)throw new Error('worker-completion-mismatch');
      completed=msg.status;phase='closed-await';return;
    }
    throw new Error('worker-wire-order');
  }
  child.stdin.on('error',()=>stop('worker-stdio-error'));
  child.on('error',()=>stop('worker-spawn-error'));
  let stderrPrefix='';
  child.stderr.on('data',chunk=>{if(stderrPrefix.length<1024)stderrPrefix+=chunk.toString('utf8',0,1024-stderrPrefix.length);});
  child.on('close',(code,childSignal)=>{
    closedResolve({code,childSignal});
    if(code===0&&completed&&pending.length===0)stop(completed);
    else if(!checks&&stderrPrefix.includes('sandbox-exec: sandbox_apply: Operation not permitted'))stop('launcher-blocked');
    else stop('worker-incomplete');
  });
  child.stdout.on('data',chunk=>{
    if(ending)return;
    total+=chunk.length;
    if(total>MAX_TOTAL){stop('worker-wire-byte-limit');return;}
    pending=Buffer.concat([pending,chunk]);
    try{
      for(let ix;(ix=pending.indexOf(10))>=0;){
        const line=pending.subarray(0,ix);pending=pending.subarray(ix+1);processLine(line);
      }
      if(pending.length>MAX_LINE)stop('worker-wire-line-limit');
    }catch{stop('worker-wire-rejected');}
  });
  let why=await done;
  clearTimeout(timer);
  signal?.removeEventListener('abort',aborted);
  const cleanup=await boundedClose(child,closed);
  if(!cleanup.groupGone)why='worker-cleanup-incomplete';
  return {status:['completed','blocked'].includes(why)?why:'failed',reason:why,checks,requestCount,bindingDenied,decision,callbackReason,cleanup};
}
async function verifyAbsoluteFile(p,task) {
  const full=resolve(p);
  if(full.startsWith(task+sep)||full===task||await realpath(full)!==full||!(await lstat(full)).isFile())throw new Error('synthetic-canary-invalid');
  return full;
}
/** Fixtures only, never pass real filesystem files or arbitrary worker text to this API. */
export async function runIsolatedAgentWorker({taskDir,scenario='clean',invoke=()=>({decision:'block',reason:'policy'}),loopbackPort,outsideCanaryPath,peerCanaryPath,jobId,foreignJobId,onForeignBindingDenied=()=>{},signal,timeoutMs=8000}) {
  if(process.platform!=='darwin'||!scenarios.has(scenario)||typeof invoke!=='function'||!/^[a-f0-9]{12,64}$/.test(jobId??'')||
     !Number.isInteger(loopbackPort)||loopbackPort<1||loopbackPort>65535||!Number.isInteger(timeoutMs)||timeoutMs<400||timeoutMs>30000)
    throw new Error('invalid-isolated-worker-fixture');
  if(scenario==='cross-binding'&&(!/^[a-f0-9]{12,64}$/.test(foreignJobId??'')||jobId===foreignJobId||typeof onForeignBindingDenied!=='function'))
    throw new Error('invalid-worker-binding-fixture');
  if(scenario!=='cross-binding'&&foreignJobId!==undefined)throw new Error('unexpected-worker-binding-fixture');
  const task=resolve(taskDir);
  if(await realpath(task)!==task)throw new Error('task-canonical-path-required');
  const st=await lstat(task);
  if(!st.isDirectory()||st.uid!==process.getuid()||(st.mode&0o077))throw new Error('task-directory-not-private');
  const host=await verifyAbsoluteFile(outsideCanaryPath,task),peer=await verifyAbsoluteFile(peerCanaryPath,task);
  if(host===peer)throw new Error('distinct-synthetic-canaries-required');
  if(signal?.aborted)return {status:'failed',reason:'aborted',checks:null,requestCount:0,bindingDenied:0,decision:null,callbackReason:null,cleanup:{groupGone:true,forced:false,scope:'no process started'}};
  return launch({task,scenario,invoke,port:loopbackPort,host,peer,jobId,foreignJobId,onForeignBindingDenied,signal,timeoutMs});
}

async function selfTest() {
  const root=dirname(fileURLToPath(import.meta.url)), runs=join(root,'runs');
  await mkdir(runs,{mode:0o700,recursive:true});
  if(!((await lstat(runs)).isDirectory())||await realpath(runs)!==runs)throw new Error('run-directory-invalid');
  const run=await mkdtemp(join(runs,'isolated-agent-'));
  const host=join(run,'synthetic-host'),peer=join(run,'synthetic-peer');
  await Promise.all([writeFile(host,'SYNTHETIC_HOST',{mode:0o600,flag:'wx'}),writeFile(peer,'SYNTHETIC_PEER',{mode:0o600,flag:'wx'})]);
  let observed=0;
  const listener=createServer(s=>{observed++;s.end();});
  await new Promise((yes,no)=>{listener.once('error',no);listener.listen(0,'127.0.0.1',yes);});
  const loopbackPort=listener.address().port;
  const make=async scenario=>{
    const taskDir=join(run,scenario);await mkdir(taskDir,{mode:0o700});
    return {taskDir,scenario,loopbackPort,outsideCanaryPath:host,peerCanaryPath:peer,jobId:randomBytes(12).toString('hex')};
  };
  try {
    await new Promise((yes,no)=>{const s=connect({host:'127.0.0.1',port:loopbackPort});s.once('error',no);s.once('end',yes);});
    const control=observed;
    const marks={};let forwarded=0;
    const invoke=async req=>{forwarded++;return {decision:req.text===inputs.clean?'allow':'block',reason:'policy'};};
    const prior=process.env.ATOMIUM_WORKER_FAKE_KEY;
    process.env.ATOMIUM_WORKER_FAKE_KEY='SYNTHETIC_ONLY';
    try {
      for(const scenario of ['clean','canary','unsupported-route','no-request','hang'])marks[scenario]=await runIsolatedAgentWorker({...await make(scenario),invoke,timeoutMs:scenario==='hang'?1200:8000});
      const controller=new AbortController();
      const signal=controller.signal;
      const opts={...await make('abort-fixture'),scenario:'hang',invoke,signal};
      const timer=setTimeout(()=>controller.abort(),150);
      try {marks.abort=await runIsolatedAgentWorker(opts);}finally{clearTimeout(timer);}
    } finally {if(prior===undefined)delete process.env.ATOMIUM_WORKER_FAKE_KEY;else process.env.ATOMIUM_WORKER_FAKE_KEY=prior;}
    const expected={clean:'completed',canary:'blocked','unsupported-route':'blocked','no-request':'completed',hang:'failed',abort:'failed'};
    const statuses=Object.entries(expected).every(([key,want])=>marks[key].status===want);
    const probes=['clean','canary','unsupported-route','no-request'].every(k=>marks[k].checks&&Object.values(marks[k].checks).every(Boolean));
    const ok=statuses&&probes&&control===1&&observed===control&&forwarded===2&&marks.hang.reason==='timed-out'&&marks.abort.reason==='aborted'&&Object.values(marks).every(r=>r.cleanup.groupGone);
    await writeFile(join(run,'evidence.json'),JSON.stringify({mode:'isolated-worker-self-test',status:ok?'passed':'failed',controlConnections:control,workerConnections:observed-control,forwarded,marks},null,2)+'\n',{mode:0o600,flag:'wx'});
    console.log('Evidence: '+join(run,'evidence.json'));
    if(!ok)process.exitCode=1;
  }finally {await new Promise(yes=>listener.close(yes));}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv[2]==='--self-test'&&process.argv.length===3)await selfTest();
  else {console.error('Usage: node isolated-agent-worker.mjs --self-test');process.exitCode=2;}
}
