import { createServer } from 'node:http';
import { randomBytes,createHash } from 'node:crypto';
import { lstat,mkdir,mkdtemp,realpath,writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFixtureGateway,CANARY,FIXTURE_ROUTE } from './egress-gateway.mjs';
import { runIsolatedAgentWorker } from './isolated-agent-worker.mjs';

const runs=fileURLToPath(new URL('./runs',import.meta.url));
const job=()=>randomBytes(12).toString('hex');
const request=(jobId,text='Summarize synthetic item A.',route=FIXTURE_ROUTE)=>({type:'model-request',route,jobId,text});
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

async function server(handler){
  const instance=createServer(handler);
  instance.requestTimeout=2500;
  const counts={connections:0,requests:0,accepted:0,markerRequests:0};
  instance.on('connection',()=>counts.connections++);
  await new Promise((resolve,reject)=>{
    instance.once('error',reject);instance.listen(0,'127.0.0.1',resolve);
  });
  return {port:instance.address().port,counts,close:()=>new Promise(resolve=>{
    if(!instance.listening)return resolve();
    instance.close(()=>resolve());
    instance.closeAllConnections();
  })};
}

export async function runAgentEgressAudit(){
  if(process.platform!=='darwin')throw new Error('verify-agent-egress is macOS-only');
  await mkdir(runs,{recursive:true,mode:0o700});
  if(!(await lstat(runs)).isDirectory()||await realpath(runs)!==runs)throw new Error('unsafe-run-root');
  const dir=await realpath(await mkdtemp(join(runs,'agent-egress-')));
  const host=join(dir,'synthetic-host'),peer=join(dir,'synthetic-peer');
  await mkdir(host,{mode:0o700});await mkdir(peer,{mode:0o700});
  const outsideCanaryPath=join(host,'marker'),peerCanaryPath=join(peer,'marker');
  const marker='Atomium fixed marker outside task; not a credential\n';
  await writeFile(outsideCanaryPath,marker,{mode:0o600,flag:'wx'});
  await writeFile(peerCanaryPath,marker,{mode:0o600,flag:'wx'});
  const checks=[];
  const add=(id,pass,extra={})=>{
    checks.push({id,pass:Boolean(pass),...extra});
    console.log((pass?'PASS ':'FAIL ')+id);
  };
  const redirectTarget=await server((_req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end('{"ok":true}');});
  let upstream=null,gateway=null,mode='ack';
  let onReceive=()=>{};
  try {
    upstream=await server((req,res)=>{
      upstream.counts.requests++;
      if(req.method!=='POST'||req.url!=='/model/v1'||req.headers['content-type']!=='application/json'){
        res.writeHead(400);res.end();return;
      }
      let body='',size=0;
      req.on('data',chunk=>{
        size+=chunk.length;
        if(size>1024){res.destroy();return;}
        body+=chunk.toString('utf8');
      });
      req.on('end',()=>{
        if(size>1024)return;
        let text;
        try{text=JSON.parse(body).text;}catch{}
        if(typeof text!=='string'){res.writeHead(400);res.end();return;}
        if(text.includes(CANARY))upstream.counts.markerRequests++;
        upstream.counts.accepted++;
        onReceive();
        if(mode==='hold')return;
        if(mode==='redirect'){
          res.writeHead(302,{Location:'http://127.0.0.1:'+redirectTarget.port+'/fixture'});res.end();return;
        }
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end('{"ok":true}');
      });
    });
    gateway=createFixtureGateway({port:upstream.port});
    const startWorker=async (scenario,{taskName=scenario,signal}={})=>{
      const taskDir=join(dir,'task-'+taskName);
      await mkdir(taskDir,{mode:0o700});
      const jobId=job();
      if(!gateway.grant(jobId,9000))throw new Error('cannot-grant-fixture');
      const before={...upstream.counts};
      let result={status:'failed'}, callback=null;
      const parentMarker='ATOMIUM_WORKER_FAKE_KEY', prior=process.env[parentMarker];
      try{
        process.env[parentMarker]='SYNTHETIC_ONLY';
        result=await runIsolatedAgentWorker({
          taskDir,scenario,jobId,loopbackPort:upstream.port,outsideCanaryPath,peerCanaryPath,signal,
          invoke:(row,{signal:workerSignal}={})=>{
            const abort=()=>gateway.revoke(jobId);
            workerSignal?.addEventListener('abort',abort,{once:true});
            if(workerSignal?.aborted)abort();
            callback=gateway.invoke(row).finally(()=>workerSignal?.removeEventListener('abort',abort));
            return callback;
          },
        });
      }catch{}finally{
        gateway.revoke(jobId);
        if(prior===undefined)delete process.env[parentMarker];else process.env[parentMarker]=prior;
      }
      return {result,jobId,callbackResult:await callback,connections:upstream.counts.connections-before.connections,received:upstream.counts.accepted-before.accepted};
    };
    const clean=await startWorker('clean');
    const red=await startWorker('canary');
    const workerSummary=row=>({
      status:row.result.status,requestCount:row.result.requestCount,decision:row.result.decision,
      checks:row.result.checks,cleanup:row.result.cleanup,
      upstreamConnections:row.connections,upstreamAccepted:row.received,
    });
    const c=clean.result;
    const allBoundary=['taskReadWrite','networkDenied','hostReadDenied','peerReadDenied','cleanEnvironment'].every(key=>c.checks?.[key]===true);
    add('isolated-worker-positive-controls-and-denials',allBoundary&&c.cleanup?.groupGone===true,{worker:workerSummary(clean)});
    add('permitted-request-via-gateway-once',c.status==='completed'&&c.decision==='allow'&&clean.callbackResult?.reason==='fixture-upstream-ack'&&c.requestCount===1&&clean.connections===1&&clean.received===1,{worker:workerSummary(clean)});
    add('synthetic-marker-blocked-before-transport',red.result.status==='blocked'&&red.result.decision==='block'&&red.callbackResult?.reason==='canary'&&red.result.cleanup?.groupGone===true&&red.result.requestCount===1&&red.connections===0&&red.received===0&&upstream.counts.markerRequests===0,{worker:workerSummary(red)});

    const singleJob=job(), beforeSingle=upstream.counts.accepted;
    if(!gateway.grant(singleJob))throw new Error('cannot-grant-single-use-control');
    const first=await gateway.invoke(request(singleJob));
    const repeat=await gateway.invoke(request(singleJob));
    add('single-use-while-grant-still-current',first.decision==='allow'&&repeat.reason==='grant-unavailable'&&upstream.counts.accepted===beforeSingle+1);

    const b0={...upstream.counts};
    const j=job(), revoked=job(), malformed=job(), expired=job();
    if(!gateway.grant(j)||!gateway.grant(revoked)||!gateway.grant(malformed)||!gateway.grant(expired,1))throw new Error('cannot-grant-controls');
    gateway.revoke(revoked);
    await sleep(5);
    const wrong=await gateway.invoke(request(j,'same fixture','other-route'));
    const reused=await gateway.invoke(request(clean.jobId));
    const closedGrant=await gateway.invoke(request(revoked));
    const expiredGrant=await gateway.invoke(request(expired));
    const bad=await gateway.invoke({...request(malformed),url:'not-a-routing-input'});
    const large=await gateway.invoke(request(malformed,'x'.repeat(1100)));
    add('route-and-request-schema-denied',wrong.reason==='route-denied'&&bad.reason==='schema'&&large.reason==='body-limit'&&upstream.counts.connections===b0.connections);
    add('replay-revoked-and-expired-grants-denied',reused.reason==='grant-unavailable'&&closedGrant.reason==='grant-unavailable'&&expiredGrant.reason==='grant-unavailable'&&upstream.counts.connections===b0.connections);

    mode='redirect';
    const redirectJob=job();
    if(!gateway.grant(redirectJob))throw new Error('cannot-grant-redirect-control');
    const redirected=await gateway.invoke(request(redirectJob));
    add('upstream-redirect-not-followed',redirected.reason==='upstream-failed'&&redirectTarget.counts.connections===0);

    mode='hold';
    const pendingJob=job();
    if(!gateway.grant(pendingJob))throw new Error('cannot-grant-revoke-control');
    let received;
    const arrived=new Promise(resolve=>{received=resolve;});
    onReceive=received;
    const pending=gateway.invoke(request(pendingJob));
    let timer;
    const didArrive=await Promise.race([arrived.then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),1000);})]);
    clearTimeout(timer);onReceive=()=>{};
    gateway.revoke(pendingJob);
    const canceled=await pending;
    add('revoke-inflight-fails-closed',didArrive&&canceled.reason==='grant-unavailable',{upstreamAlreadyReceived:didArrive});

    const abortWorker=new AbortController();
    const workerTimer=setTimeout(()=>abortWorker.abort(),3500);
    onReceive=()=>abortWorker.abort();
    let abortRun;
    try {abortRun=await startWorker('clean',{taskName:'cancel-inflight',signal:abortWorker.signal});}
    finally {clearTimeout(workerTimer);onReceive=()=>{};}
    add('cancel-worker-revokes-its-inflight-request',abortRun.result.reason==='aborted'&&abortRun.result.cleanup?.groupGone===true&&abortRun.received===1&&abortRun.callbackResult?.reason==='grant-unavailable',{
      worker:workerSummary(abortRun),revokeResult:abortRun.callbackResult?.reason??null,upstreamAlreadyReceived:abortRun.received===1,
    });

    await upstream.close();
    const outageJob=job();
    if(!gateway.grant(outageJob))throw new Error('cannot-grant-outage-control');
    const outage=await gateway.invoke(request(outageJob));
    const again=await gateway.invoke(request(outageJob));
    add('upstream-down-no-direct-fallback',outage.reason==='upstream-failed'&&again.reason==='grant-unavailable'&&redirectTarget.counts.connections===0);
    gateway.stop();
    const stopped=await gateway.invoke(request(job()));
    add('stopped-gateway-denies',stopped.reason==='gateway-closed');
    const evidence={
      version:1,scope:'fixed synthetic macOS worker and local test upstream only',
      checks,upstream:{...upstream.counts,redirectConnections:redirectTarget.counts.connections},
      decisions:gateway.evidence(),recordDigest:digest(JSON.stringify(checks)),
      usedRealProvider:false,receivedCredentials:false,exported:false,
      uncovered:['real Agent isolation','Linux guest boundary','real provider/API authorization','general DLP','non-local network enforcement probes','browser and unattended operation'],
    };
    await writeFile(join(dir,'evidence.json'),JSON.stringify(evidence,null,2)+'\n',{mode:0o600,flag:'wx'});
    console.log('Evidence: '+join(dir,'evidence.json'));
    return checks.every(x=>x.pass);
  }finally{
    gateway?.stop();
    await upstream?.close();
    await redirectTarget.close();
  }
}
