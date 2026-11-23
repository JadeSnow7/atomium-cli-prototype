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
      const ok=await postFixture(port,data,controller.signal);
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
