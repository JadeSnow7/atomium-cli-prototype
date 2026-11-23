import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { lstat,mkdir,mkdtemp,realpath,writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFixtureGateway,FIXTURE_ROUTE,bindFixtureChannel,verifyFixtureGatewayProtocolState } from './egress-gateway.mjs';
import { runIsolatedAgentWorker,verifyWorkerProtocolFixture } from './isolated-agent-worker.mjs';

const runs=fileURLToPath(new URL('./runs',import.meta.url));
const A='Summarize synthetic item A.',B='Summarize synthetic item B.';
const packet=(jobId,text)=>({type:'model-request',route:FIXTURE_ROUTE,jobId,text});
const job=()=>randomBytes(12).toString('hex');
const deferred=()=>{let done;const promise=new Promise(resolve=>{done=resolve;});return {promise,done};};
export async function runDualWorkerProtocolOnly(){
  await mkdir(runs,{recursive:true,mode:0o700});
  if(!(await lstat(runs)).isDirectory()||await realpath(runs)!==runs)throw new Error('unsafe-run-root');
  const dir=await mkdtemp(join(runs,'dual-worker-protocol-'));
  let state;
  try{state=await verifyFixtureGatewayProtocolState();}
  catch{state={roles:{A:null,B:null},checks:[{id:'mock-gateway-state-test-unavailable',pass:false}]};}
  const checks=[...verifyWorkerProtocolFixture(),...state.checks];
  const report={version:1,mode:'verify-dual-worker-protocol-only',status:checks.every(c=>c.pass)?'passed':'failed',
    checks,roles:state.roles,realSubprocesses:0,realNetworkRequests:0,
    notCovered:['OS sandbox','receiver traffic','real in-flight connection closure']};
  await writeFile(join(dir,'evidence.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
  for(const item of checks)console.log((item.pass?'PASS ':'FAIL ')+item.id);
  console.log('Protocol only: simulated transport; no OS sandbox, receiver or live connection claims.');
  console.log('Evidence: '+join(dir,'evidence.json'));
  return report;
}
async function deadline(p,ms,label){
  let timer;
  try{return await Promise.race([p,new Promise(yes=>{timer=setTimeout(()=>yes(label),ms);})]);}
  finally{clearTimeout(timer);}
}
const workerChecks=r=>Boolean(r?.checks)&&Object.values(r.checks).every(Boolean);
const normalize=r=>r?{status:r.status,reason:r.reason,requestCount:r.requestCount,bindingDenied:r.bindingDenied,checks:r.checks,cleanup:r.cleanup,decision:r.decision}:null;

export async function runDualWorkerDemo(){
  if(process.platform!=='darwin')throw new Error('verify-dual-worker is macOS-only');
  await mkdir(runs,{recursive:true,mode:0o700});
  if(!(await lstat(runs)).isDirectory()||await realpath(runs)!==runs)throw new Error('unsafe-run-root');
  const dir=await realpath(await mkdtemp(join(runs,'dual-worker-')));
  const taskA=join(dir,'task-A'),taskB=join(dir,'task-B');
  await Promise.all([taskA,taskB].map(d=>mkdir(d,{mode:0o700})));
  const outsideCanaryPath=join(dir,'host-marker');
  const aPeer=join(taskA,'peer-marker'),bPeer=join(taskB,'peer-marker');
  await Promise.all([outsideCanaryPath,aPeer,bPeer].map(p=>writeFile(p,'SYNTHETIC_FIXTURE_NOT_A_CREDENTIAL',{mode:0o600,flag:'wx'})));
  const counts={connections:0,requests:0,A:0,B:0,unexpected:0};const events=[];
  const channel=role=>'supervisor-bound-stdio-'+role;
  const mark=(kind,role,detail={})=>events.push({sequence:events.length+1,kind,role,channel:channel(role),...detail});
  const seenA=deferred(),closedA=deferred(),foreignB=deferred(),resumeB=deferred(),stopped=deferred();
  const controllerA=new AbortController(),controllerB=new AbortController();
  const listener=createServer((req,res)=>{
    counts.requests++;
    if(req.method!=='POST'||req.url!=='/model/v1'||req.headers['content-type']!=='application/json'){
      counts.unexpected++;res.writeHead(400);res.end();return;
    }
    let body=Buffer.alloc(0);
    req.on('data',part=>{if(body.length+part.length>1024){counts.unexpected++;req.destroy();return;}body=Buffer.concat([body,part]);});
    req.on('end',()=>{
      // Match only the two canonical synthetic request bodies; never log raw bytes.
      if(body.equals(Buffer.from(JSON.stringify({text:A})))){
        counts.A++;mark('receiver-A-arrived','A');seenA.done();
        res.once('close',()=>{mark('receiver-A-aborted','A');closedA.done(true);});
        return; // Keep A in flight; revocation must close this transport.
      }
      if(body.equals(Buffer.from(JSON.stringify({text:B})))){
        counts.B++;mark('receiver-B-arrived','B');res.writeHead(200,{'Content-Type':'application/json'});res.end('{"ok":true}');return;
      }
      counts.unexpected++;res.writeHead(400);res.end();
    });
  });
  listener.on('connection',()=>counts.connections++);
  let gateway=null,a=null,b=null,resultA=null,resultB=null,afterRevoke=null,aOutcome=null,observedClose=false,phase='listener',status='failed',beforeBindingCheck=null,atOverlap=null,beforePeerRelease=null;
  let checks=[];
  try{
    await new Promise((yes,no)=>{listener.once('error',no);listener.listen(0,'127.0.0.1',yes);});
    const port=listener.address().port;
    gateway=createFixtureGateway({port,timeoutMs:4500});
    const aId=job(),bId=job();
    if(!gateway.grant(aId,8500)||!gateway.grant(bId,8500))throw new Error('cannot-grant-dual-fixture');
    function ownChannel(role,jobId) {
      const bound=bindFixtureChannel(gateway,jobId);
      return (row,options)=>{
        const origin=options?.origin==='trusted-supervisor-harness'?'trusted-supervisor-harness':'isolated-worker';
        mark('controller-'+role+'-request',role,{origin});
        const result=bound(row,options).then(value=>{
          mark(value.reason==='channel-binding-mismatch'?'supervisor-channel-decision':'gateway-decision',role,{origin,decision:value.decision,reason:value.reason});
          return value;
        });
        if(role==='A'&&origin==='isolated-worker'&&!aOutcome)aOutcome=result;
        return result;
      };
    }
    const invokeA=ownChannel('A',aId),invokeB=ownChannel('B',bId);
    const base={loopbackPort:port,outsideCanaryPath,timeoutMs:8000};
    const launch=(name,options)=>{
      mark('controller-'+name+'-started',name);
      return runIsolatedAgentWorker({...base,...options}).then(r=>{
        mark('controller-'+name+'-finished',name,{status:r.status,groupGone:r.cleanup?.groupGone??null});
        if(r.status==='failed')stopped.done(r.reason);
        return r;
      },()=>{stopped.done('worker-setup-failed');return {status:'failed',reason:'worker-setup-failed'};});
    };
    phase='overlap';
    a=launch('A',{taskDir:taskA,jobId:aId,peerCanaryPath:bPeer,invoke:invokeA,signal:controllerA.signal});
    b=launch('B',{taskDir:taskB,jobId:bId,foreignJobId:aId,scenario:'cross-binding',peerCanaryPath:aPeer,invoke:invokeB,signal:controllerB.signal,
      onForeignBindingDenied:async (row,{signal})=>{
        // Validate the foreign claim with the same supervisor binding used for
        // normal traffic and by the independent protocol fallback. Never call
        // a raw/unbound gateway method here.
        if(!await deadline(seenA.promise.then(()=>true),3500,false)||signal.aborted)throw new Error('A-delivery-not-observed');
        beforeBindingCheck={...counts};
        const refusal=await invokeB(row,{signal});
        if(refusal.decision!=='block'||refusal.reason!=='channel-binding-mismatch')throw new Error('foreign-binding-not-rejected');
        mark('worker-B-foreign-binding-denied','B',{claimedOwner:'fixture-A',origin:'trusted-supervisor-channel',decision:'block',reason:refusal.reason});
        foreignB.done();await resumeB.promise;
      },
    });
    const barrier=await deadline(Promise.race([Promise.all([seenA.promise,foreignB.promise]).then(()=>true),stopped.promise]),3500,'overlap-timeout');
    if(barrier!==true){
      phase=barrier==='launcher-blocked'?'launcher-blocked':'overlap-unavailable';
      await Promise.all([a,b].map(async (p,i)=>{if(i===0)controllerA.abort();else controllerB.abort();await p;}));
      resultA=await a;resultB=await b;
      status=phase==='launcher-blocked'?'blocked':'failed';
    }else{
      phase='revocation';
      atOverlap={...counts};
      mark('controller-A-revoke','A');
      gateway.revoke(aId);controllerA.abort();
      // Fixed supervisor-side harness injection, through the original A-bound
      // callback; it is NOT attributed to a cancelled or dead worker.
      mark('harness-A-after-revoke','A');
      afterRevoke=await invokeA(packet(aId,A),{origin:'trusted-supervisor-harness'});
      resultA=await a;
      observedClose=await deadline(closedA.promise,1000,false);
      if(aOutcome)aOutcome=await aOutcome;
      beforePeerRelease={...counts};
      mark('controller-B-released','B');
      resumeB.done();
      resultB=await b;
      const order=(first,second)=>events.findIndex(e=>e.kind===first)>=0&&events.findIndex(e=>e.kind===second)>events.findIndex(e=>e.kind===first);
      checks=[
        ['independent-worker-boundaries',workerChecks(resultA)&&workerChecks(resultB)],
        ['worker-overlap-before-revocation',order('controller-A-started','worker-B-foreign-binding-denied')&&order('controller-B-started','receiver-A-arrived')&&order('receiver-A-arrived','controller-A-revoke')&&order('worker-B-foreign-binding-denied','controller-A-revoke')],
        ['A-delivered-once-before-revoke',counts.A===1&&order('receiver-A-arrived','controller-A-revoke')&&aOutcome?.decision==='block'&&aOutcome?.reason==='grant-unavailable'],
        ['B-foreign-binding-denied-without-forwarding',resultB.bindingDenied===1&&resultB.requestCount===2&&counts.unexpected===0&&atOverlap.A===1&&atOverlap.B===0&&atOverlap.requests===1&&atOverlap.connections===1&&Object.keys(atOverlap).every(k=>beforeBindingCheck?.[k]===atOverlap[k])&&order('receiver-A-arrived','worker-B-foreign-binding-denied')&&order('worker-B-foreign-binding-denied','controller-A-revoke')],
        ['A-revocation-closes-in-flight',observedClose===true&&order('controller-A-revoke','receiver-A-aborted')&&resultA.reason==='aborted'&&resultA.cleanup?.groupGone],
        ['A-next-bound-request-refused',afterRevoke?.decision==='block'&&afterRevoke?.reason==='grant-unavailable'&&counts.A===1&&beforePeerRelease.A===1&&beforePeerRelease.B===0&&beforePeerRelease.requests===1&&beforePeerRelease.connections===1],
        ['B-completes-after-A-cleanup',resultB.status==='completed'&&resultB.decision==='allow'&&resultB.cleanup?.groupGone&&counts.B===1&&order('controller-A-finished','receiver-B-arrived')],
        ['independent-receiver-exact-counts',counts.connections===2&&counts.requests===2&&counts.A===1&&counts.B===1&&counts.unexpected===0],
      ].map(([id,pass])=>({id,pass:Boolean(pass)}));
      status=checks.every(x=>x.pass)?'passed':'failed';phase='completed';
    }
  }catch(e){
    if(phase==='listener'&&['EPERM','EACCES'].includes(e.code)){phase='listener-blocked';status='blocked';}
    else {phase='fixture-execution-error';status='failed';}
  }finally{
    gateway?.stop();
    controllerA.abort();controllerB.abort();resumeB.done();
    if(a)resultA??=await a;
    if(b)resultB??=await b;
    if(listener.listening)await new Promise(yes=>{listener.close(yes);listener.closeAllConnections();});
  }
  const receipt={version:1,mode:'verify-dual-worker',status,phase,checks,receiver:counts,receiverCheckpoints:{beforeBindingCheck,atOverlap,beforePeerRelease},
    workers:Object.fromEntries([['A',resultA],['B',resultB]].map(([role,result])=>[role,{
      owner:'fixture-'+role,channel:channel(role),observation:normalize(result),
      orderedDecisions:events.filter(e=>e.role===role&&(e.decision||e.kind.endsWith('-revoke'))),
    }])),afterRevoke:afterRevoke?{origin:'trusted-supervisor-harness',...afterRevoke}:null,
    originalAOutcome:aOutcome?.decision?aOutcome:null,events,gatewayDecisions:gateway?.evidence()??[],exportAvailable:false,
    notCovered:['real provider or login','general process or metadata isolation','non-IPv4-loopback rule tests','production egress or DLP','Linux or browser'],
  };
  await writeFile(join(dir,'evidence.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
  for(const row of checks)console.log((row.pass?'PASS ':'FAIL ')+row.id);
  console.log((status==='passed'?'PASS ':status==='blocked'?'BLOCKED ':'FAIL ')+phase);
  console.log('Evidence: '+join(dir,'evidence.json'));
  return receipt;
}
