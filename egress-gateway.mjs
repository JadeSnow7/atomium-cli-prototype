import { request } from 'node:http';
import { connect } from 'node:net';

export const FIXTURE_ROUTE='fixture-model';
export const CANARY='ATOMIUM_DLP_CANARY_V1';
const limit=1024;
const maxJobs=32;
const jobPattern=/^[a-f0-9]{24}$/;

// This is a supervisor-owned RPC gate, not a remote HTTP proxy. No user URL,
// token, HTTP method/header or redirect ever comes from the worker.
export function createFixtureGateway({port,timeoutMs=1200}) {
  return fixtureGateway({port,timeoutMs,post:postFixture});
}
function fixtureGateway({port,timeoutMs,post}) {
  if(!Number.isInteger(port)||port<1024||port>65535||!Number.isInteger(timeoutMs)||timeoutMs<20||timeoutMs>5000)throw new Error('invalid-gateway-config');
  const jobs=new Map();
  const audit=[];
  let closed=false;
  const record=(decision,reason)=>{
    if(audit.length<128)audit.push({decision,reason});
    return {decision,reason};
  };
  function grant(jobId,ttlMs=4000){
    if(closed||typeof jobId!=='string'||!jobPattern.test(jobId)||jobs.has(jobId)||jobs.size>=maxJobs||ttlMs<1||ttlMs>10000||!Number.isInteger(ttlMs))return false;
    jobs.set(jobId,{expiresAt:performance.now()+ttlMs,state:'ready',controller:null});
    return true;
  }
  function revoke(jobId){
    const entry=jobs.get(jobId);
    if(!entry)return false;
    entry.state='revoked';
    entry.controller?.abort();
    return true;
  }
  function stop(){
    closed=true;
    for(const jobId of jobs.keys())revoke(jobId);
  }
  async function invoke(msg){
    if(closed)return record('block','gateway-closed');
    if(!msg||typeof msg!=='object'||Array.isArray(msg)||Object.keys(msg).sort().join(',')!=='jobId,route,text,type'||
      msg.type!=='model-request'||typeof msg.jobId!=='string'||!jobPattern.test(msg.jobId)||
      typeof msg.route!=='string'||typeof msg.text!=='string'||msg.text.length===0)return record('block','schema');
    const entry=jobs.get(msg.jobId);
    if(!entry||entry.state!=='ready'||performance.now()>=entry.expiresAt)return record('block','grant-unavailable');
    if(msg.route!==FIXTURE_ROUTE)return record('block','route-denied');

    // A valid route consumes the grant before inspection/transport, including failures.
    entry.state='consumed';
    const data=Buffer.from(JSON.stringify({text:msg.text}),'utf8');
    if(data.length>limit)return record('block','body-limit');
    if(/[\u0000-\u001f\u007f]/u.test(msg.text))return record('block','body-format');
    if(msg.text.includes(CANARY))return record('block','canary');
    const controller=new AbortController();
    entry.controller=controller;
    const waited=Math.min(timeoutMs,entry.expiresAt-performance.now());
    if(waited<=0){entry.controller=null;return record('block','grant-unavailable');}
    const timer=setTimeout(()=>controller.abort(),waited);
    try {
      const ok=await post(port,data,controller.signal);
      if(entry.state==='revoked'||closed)return record('block','grant-unavailable');
      return ok?record('allow','fixture-upstream-ack'):record('block','upstream-failed');
    }catch{
      return entry.state==='revoked'||closed?record('block','grant-unavailable'):record('block','upstream-failed');
    }finally{
      clearTimeout(timer);
      entry.controller=null;
    }
  }
  return {grant,revoke,stop,invoke,evidence:()=>audit.map(row=>({...row}))};
}

// The binding belongs to the supervisor's per-worker channel callback. A job ID
// echoed in a body does not establish identity, even if that job has a grant.
export function bindFixtureChannel(gateway,jobId,onRequest=()=>{}){
  if(!jobPattern.test(jobId)||typeof onRequest!=='function')throw new Error('invalid-channel-binding');
  return async (row,{signal}={})=>{
    if(row?.jobId!==jobId)return {decision:'block',reason:'channel-binding-mismatch'};
    const abort=()=>gateway.revoke(jobId);
    signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
    try {onRequest();return await gateway.invoke(row);}
    finally{signal?.removeEventListener('abort',abort);}
  };
}

// Trusted no-network adapter to exercise the actual gateway state machine.
export async function verifyFixtureGatewayProtocolState(){
  const ids={A:'a'.repeat(24),B:'b'.repeat(24)};
  let callsA=0,callsB=0,cancelledMockA=false,closedMockA;
  const started=new Promise(resolve=>{closedMockA=resolve;});
  const gateway=fixtureGateway({port:1024,timeoutMs:500,post:async(_port,data,signal)=>{
    const value=JSON.parse(data.toString('utf8')).text;
    if(value==='Synthetic A'){
      callsA++;closedMockA();
      return new Promise((resolve,reject)=>{
        const cancel=()=>{cancelledMockA=true;reject(new Error('mock transport cancelled'));};
        if(signal.aborted)cancel();else signal.addEventListener('abort',cancel,{once:true});
      });
    }
    if(value==='Synthetic B'){callsB++;return true;}
    throw new Error('invalid test fixture');
  }});
  const make=(id,text)=>({type:'model-request',route:FIXTURE_ROUTE,jobId:id,text});
  const boundA=bindFixtureChannel(gateway,ids.A),boundB=bindFixtureChannel(gateway,ids.B);
  try{
    const granted=gateway.grant(ids.A)&&gateway.grant(ids.B);
    const pendingA=boundA(make(ids.A,'Synthetic A'));
    let timer;
    try{
      if(!await Promise.race([started.then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),850);})]))
        throw new Error('mock-A-transport-start-missing');
    }finally{clearTimeout(timer);}
    const mismatched=await boundB(make(ids.A,'Synthetic B'));
    gateway.revoke(ids.A);
    const furtherA=await boundA(make(ids.A,'Synthetic A'));
    const cancelled=await pendingA;
    const matchedB=await boundB(make(ids.B,'Synthetic B'));
    return {
      roles:{A:{mockCalls:callsA,inFlight:cancelled,next:furtherA},B:{mockCalls:callsB,wrongBinding:mismatched,ownBinding:matchedB}},
      checks:[
        {id:'protocol-shared-grants',pass:granted},
        {id:'protocol-wrong-channel-job-refused',pass:mismatched.reason==='channel-binding-mismatch'&&mismatched.decision==='block'},
        {id:'protocol-in-flight-revocation-state',pass:cancelledMockA&&cancelled.reason==='grant-unavailable'},
        {id:'protocol-revoked-task-cannot-request',pass:furtherA.reason==='grant-unavailable'&&callsA===1},
        {id:'protocol-unrevoked-peer-completes',pass:matchedB.decision==='allow'&&callsB===1},
      ],
    };
  }finally{gateway.stop();}
}

function postFixture(port,data,signal){
  return new Promise((resolve,reject)=>{
    const req=request({
      host:'127.0.0.1',port,path:'/model/v1',method:'POST',agent:false,signal,
      createConnection:()=>connect({host:'127.0.0.1',port}),
      headers:{'Content-Type':'application/json','Content-Length':data.length,'Connection':'close'},
    },res=>{
      if(res.statusCode!==200||res.headers['content-type']!=='application/json'){
        res.destroy();resolve(false);return;  // Never follow redirects or read non-200 bodies.
      }
      let bytes=0,body='';
      res.on('data',part=>{
        bytes+=part.length;
        if(bytes>limit){res.destroy();resolve(false);return;}
        body+=part.toString('utf8');
      });
      res.on('end',()=>resolve(body==='{"ok":true}'));
      res.on('error',reject);
      res.on('aborted',()=>resolve(false));
    });
    req.on('error',reject);
    req.end(data);
  });
}
