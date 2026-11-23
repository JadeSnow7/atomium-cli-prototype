import {spawn} from 'node:child_process';
import {lstat,mkdir,mkdtemp,realpath,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';

const runs=fileURLToPath(new URL('./runs',import.meta.url));
const fixtures=Object.freeze({
  a:Object.freeze({profile:'fixture-a',session:'fixture-session-a',helper:'helper-a'}),
  alias:Object.freeze({profile:'fixture-alias-a',session:'fixture-session-a',helper:'helper-a'}),
  b:Object.freeze({profile:'fixture-b',session:'fixture-session-b',helper:'helper-b'}),
  offline:Object.freeze({profile:'fixture-offline',session:'fixture-session-offline',helper:'helper-offline'}),
});
const knownOp=new Set(['held','cancelled','completed','ready']);
const defer=()=>{let resolve;const promise=new Promise(ok=>{resolve=ok;});return {promise,resolve};};
async function bound(p,ms,reason='timeout'){
  let timer;
  try{return await Promise.race([p,new Promise(resolve=>{timer=setTimeout(()=>resolve({type:reason}),ms);})]);}
  finally{clearTimeout(timer);}
}
const childCode=[
  "import {createInterface} from 'node:readline';",
  "const [helper,session,cwd,home,tmp]=process.argv.slice(1);",
  "const expected=helper==='helper-a'?'fixture-session-a':helper==='helper-b'?'fixture-session-b':null;",
  "const expectedJob=helper==='helper-a'?'fixed-job-a':'fixed-job-b';",
  "if(expected!==session||process.cwd()!==cwd||process.env.HOME!==home||process.env.TMPDIR!==tmp||Object.keys(process.env).filter(k=>k!=='__CF_USER_TEXT_ENCODING').sort().join(',')!=='HOME,LANG,PATH,TMPDIR')process.exit(4);",
  "const send=(type,job=null)=>process.stdout.write(JSON.stringify({type,helper,session,job,pid:process.pid})+'\\n');",
  "const ui=createInterface({input:process.stdin});",
  "send('ready');",
  "let active=false;",
  "for await(const line of ui){",
  "  if (line.length>1024) {process.exitCode=5;break;}",
  "  let p;try{p=JSON.parse(line);}catch{process.exitCode=5;break;}",
  "  if(!p||JSON.stringify(p)!==line||Object.keys(p).sort().join(',')!=='job,session,type'||p.session!==session||p.job!==expectedJob){process.exitCode=6;break;}",
  "  if(p.type==='start'&&!active){active=true;send('held',p.job);continue;}",
  "  else if(active&&p.type==='stop'){send('cancelled',p.job);break;}",
  "  else if(active&&p.type==='finish'){send('completed',p.job);break;}",
  "  process.exitCode=7;break;",
  "}",
  "ui.close();process.stdin.destroy();",
].join('\n');

function group(pid,signal){
  if(!Number.isInteger(pid)||pid<2)return false;
  try{process.kill(-pid,signal);return true;}
  catch(e){if(e.code==='ESRCH')return false;throw e;}
}
async function launch(fixture,base){
  const cwd=join(base,fixture.helper),home=join(cwd,'home'),tmp=join(cwd,'tmp');
  await mkdir(cwd,{mode:0o700});
  await Promise.all([mkdir(home,{mode:0o700}),mkdir(tmp,{mode:0o700})]);
  const child=spawn(process.execPath,['--input-type=module','-e',childCode,fixture.helper,fixture.session,cwd,home,tmp],{
    cwd,env:{HOME:home,TMPDIR:tmp,PATH:'/usr/bin:/bin',LANG:'C'},stdio:['pipe','pipe','ignore'],detached:true,
  });
  const closed=defer(),queue=[];
  let waiting=null,buffer=Buffer.alloc(0),len=0,bad=null,close=null,sent=0;
  const feed=value=>{if(waiting){waiting(value);waiting=null;}else queue.push(value);};
  const fail=reason=>{if(!bad){bad=reason;feed({type:reason});}};
  child.on('error',()=>fail('spawn-error'));
  child.stdin.on('error',()=>fail('write-error'));
  child.on('close',(code,signal)=>{close={code,signal};closed.resolve(close);if(!queue.length&&waiting)feed({type:'closed'});});
  child.stdout.on('data',chunk=>{
    if(bad)return;
    len+=chunk.length;
    if(len>8192){fail('wire-limit');return;}
    buffer=Buffer.concat([buffer,chunk]);
    for(let i;(i=buffer.indexOf(10))>=0;){
      const bytes=buffer.subarray(0,i);buffer=buffer.subarray(i+1);
      try{
        const raw=bytes.toString('utf8');
        const row=JSON.parse(raw);
        if(raw.length>1024||JSON.stringify(row)!==raw||Object.keys(row).sort().join(',')!=='helper,job,pid,session,type'||
           row.helper!==fixture.helper||row.session!==fixture.session||row.pid!==child.pid||!knownOp.has(row.type)||
           row.job!==(row.type==='ready'?null:fixture.helper==='helper-a'?'fixed-job-a':'fixed-job-b')||queue.length>=4)throw new Error();
        feed(row);
      }catch{fail('invalid-wire-reply');return;}
    }
    if(buffer.length>1024)fail('wire-line-limit');
  });
  async function expect(type,signal){
    const abort=defer(),aborted=()=>abort.resolve({type:'aborted'});
    signal?.addEventListener('abort',aborted,{once:true});if(signal?.aborted)aborted();
    try{
      if(bad)throw new Error(bad);
      const next=queue.length?Promise.resolve(queue.shift()):close?Promise.resolve({type:'closed'}):new Promise(yes=>{waiting=yes;});
      const row=await bound(Promise.race([next,abort.promise]),2400,'response-timeout');
      if(row.type!==type||bad)throw new Error(bad??row.type);
      return row;
    }finally{waiting=null;signal?.removeEventListener('abort',aborted);}
  }
  function dispatch(type,job){
    if(close||bad||!child.stdin.writable)throw new Error('helper-not-writable');
    sent++;
    child.stdin.write(JSON.stringify({type,session:fixture.session,job})+'\n');
  }
  const alive=()=>!close&&child.exitCode===null&&child.signalCode===null&&group(child.pid,0);
  let terminal;
  function settle(){
    return terminal??=(async()=>{
      let forced=false;
      if(!await bound(closed.promise,250,null)){
        forced=group(child.pid,'SIGTERM');
        if(!await bound(closed.promise,350,null))forced=group(child.pid,'SIGKILL')||forced;
      }
      child.stdin.destroy();
      await bound(closed.promise,600,null);
      return {exit:close,groupGone:!group(child.pid,0),forced,reaped:close!==null};
    })();
  }
  return {fixture,cwd,home,tmp,pid:child.pid,expect,dispatch,alive,settle,sent:()=>sent};
}

function controller(routes,helpers,mark){
  const profiles=new Map(routes.map(row=>[row.profile,row]));
  const leases=new Map();
  const inspect=(profile,expected)=>{
    const route=profiles.get(profile), backend=route&&helpers.get(route.session);
    if(!route)return {status:'profile-not-found'};
    if(expected!==route.session||backend&&backend.fixture.helper!==route.helper)return {status:'binding-mismatch'};
    if(!backend||!backend.alive())return {status:'selected-helper-unavailable'};
    if(leases.has(route.session))return {status:'session-already-active'};
    return {status:'available',route,backend};
  };
  return {
    async start(profile,session,job,signal){
      const choice=inspect(profile,session);
      if(choice.status!=='available')return {status:choice.status};
      const {route,backend}=choice;
      const lease=Object.freeze({profile,session,job});
      leases.set(route.session,lease);
      backend.dispatch('start',job);await backend.expect('held',signal);
      mark('held',profile);
      return {status:'held',lease};
    },
    async finish(lease,operation,signal){
      if(leases.get(lease.session)!==lease)throw new Error('stale-session-lease');
      const backend=helpers.get(lease.session);
      backend.dispatch(operation,lease.job);
      const expected=operation==='stop'?'cancelled':'completed';
      mark(operation==='stop'?'cancel-requested':'completion-released',lease.profile);
      await backend.expect(expected,signal);mark(expected,lease.profile);
      const cleanup=await backend.settle();
      if(cleanup.reaped&&cleanup.groupGone)leases.delete(lease.session);
      return {status:expected,cleanup};
    },
    pending:()=>leases.size,
  };
}
export async function verifyProfileDispatch({signal}={}){
  if(process.platform!=='darwin')throw new Error('macOS-required');
  await mkdir(runs,{mode:0o700,recursive:true});
  if(await realpath(runs)!==runs||!(await lstat(runs)).isDirectory())throw new Error('unsafe-run-root');
  const dir=await mkdtemp(join(runs,'profile-dispatch-'));
  const base=await realpath(await mkdtemp(join(tmpdir(),'atomium-profile-dispatch-')));
  const events=[],mark=(event,profile)=>events.push({sequence:events.length+1,event,profile});
  let a,b,finalA=null,finalB=null,checks=[],decisions=null,error=null,phase='prepare',disposed=false;
  try{
    if(signal?.aborted)throw new Error('aborted');
    const launched=await Promise.allSettled([launch(fixtures.a,base).then(x=>{a=x;}),launch(fixtures.b,base).then(x=>{b=x;})]);
    if(launched.some(row=>row.status!=='fulfilled'))throw new Error('fixture-unavailable');
    phase='ready';
    await Promise.all([a.expect('ready',signal),b.expect('ready',signal)]);
    mark('ready',fixtures.a.profile);mark('ready',fixtures.b.profile);
    const ctr=controller(Object.values(fixtures),new Map([[fixtures.a.session,a],[fixtures.b.session,b]]),mark);
    phase='concurrent-hold';
    const [jobA,jobB]=await Promise.all([
      ctr.start(fixtures.a.profile,fixtures.a.session,'fixed-job-a',signal),
      ctr.start(fixtures.b.profile,fixtures.b.session,'fixed-job-b',signal),
    ]);
    const overlap=jobA.status==='held'&&jobB.status==='held'&&a.alive()&&b.alive()&&ctr.pending()===2;
    mark('overlap-confirmed');
    const before=[a.sent(),b.sent()];
    const alias=await ctr.start(fixtures.alias.profile,fixtures.alias.session,'fixed-job-a',signal);
    const mismatch=await ctr.start(fixtures.a.profile,fixtures.b.session,'fixed-job-b',signal);
    const unavailable=await ctr.start(fixtures.offline.profile,fixtures.offline.session,'fixed-job-a',signal);
    const after=[a.sent(),b.sent()];
    const noDispatch=before.every((n,i)=>n===after[i]);
    decisions={alias,wrongBinding:mismatch,unavailable,dispatchesBefore:before,dispatchesAfter:after};
    phase='cancel-one';
    finalA=await ctr.finish(jobA.lease,'stop',signal);
    const peerLive=b.alive()&&ctr.pending()===1;
    if(peerLive)mark('peer-still-live',fixtures.b.profile);
    finalB=await ctr.finish(jobB.lease,'finish',signal);
    checks=[
      ['two-real-helpers-explicit-routing',Number.isInteger(a.pid)&&Number.isInteger(b.pid)&&a.pid!==b.pid&&a.cwd!==b.cwd&&a.home!==b.home&&a.tmp!==b.tmp],
      ['two-jobs-held-concurrently',overlap],
      ['two-aliases-share-one-active-session-lease',alias.status==='session-already-active'],
      ['wrong-binding-and-unavailable-do-not-fallback',mismatch.status==='binding-mismatch'&&unavailable.status==='selected-helper-unavailable'&&noDispatch],
      ['A-cancelled-and-reaped-while-B-still-live',finalA.status==='cancelled'&&finalA.cleanup.reaped&&finalA.cleanup.groupGone&&!finalA.cleanup.forced&&finalA.cleanup.exit?.code===0&&peerLive],
      ['B-completes-and-session-leases-released',finalB.status==='completed'&&finalB.cleanup.reaped&&finalB.cleanup.groupGone&&!finalB.cleanup.forced&&finalB.cleanup.exit?.code===0&&ctr.pending()===0],
    ].map(([id,pass])=>({id,pass:Boolean(pass)}));
    phase='completed';
  }catch(e){
    const reasons=['aborted','invalid-wire-reply','wire-limit','wire-line-limit','spawn-error','write-error','closed','response-timeout','helper-not-writable','stale-session-lease'];
    error=signal?.aborted?'aborted':reasons.includes(e.message)?e.message:'fixture-unavailable';
  }finally{
    const settled=await Promise.all([a?.settle(),b?.settle()]);
    finalA??={status:'cleanup',cleanup:settled[0]??null};finalB??={status:'cleanup',cleanup:settled[1]??null};
    try{if(!settled.some(s=>s?.groupGone===false)){await rm(base,{recursive:true,force:true});disposed=true;}}catch{}
  }
  checks.push({id:'private-synthetic-workspaces-disposed',pass:disposed});
  const passed=phase==='completed'&&checks.length===7&&checks.every(r=>r.pass)&&!signal?.aborted;
  const status=passed?'passed':signal?.aborted?'cancelled':'failed';
  const receipt={version:1,mode:'verify-profile-dispatch',status,phase,error,checks,events,decisions,
    bindings:Object.values(fixtures),helpers:{A:{pid:a?.pid??null,channel:'controller-owned-stdio-A',final:finalA},B:{pid:b?.pid??null,channel:'controller-owned-stdio-B',final:finalB}},
    stateDisposed:disposed,realProviderCalls:0,credentialReads:0,
    scope:'Fixed synthetic Node helpers on one macOS user; separate stdio and private temp directories; no vendor, actual account, OS sandbox, or cross-UID claim'};
  const path=join(dir,'evidence.json');
  await writeFile(path,JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
  for(const item of checks)console.log((item.pass?'PASS ':'FAIL ')+item.id);
  console.log('Evidence: '+path);
  return {...receipt,evidencePath:path};
}
