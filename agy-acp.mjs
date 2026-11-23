import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,rm,lstat,realpath,readFile,writeFile,rename} from 'node:fs/promises';
import {homedir,tmpdir} from 'node:os';
import {join,resolve} from 'node:path';

const testPrompt = 'Atomium synthetic fixture. Select a JSON view for checked-off tasks only.';
export async function acpConversation({command,args,env,cwd,prompt,timeout=8000,authorization='clean-home-no-auth',signal}) {
  const child=spawn(command,args,{env,cwd,stdio:['pipe','pipe','ignore']});
  const stage={protocolVersion:null,authMethods:0,newSession:false,promptSent:false,permissionsDenied:0,otherCallsDenied:0,toolUpdates:0,authorization};
  let buffer=Buffer.alloc(0), total=0, next=0, updates='', sessionId=null, fatal=null;
  const waits=new Map();
  const fail=code=>{
    fatal??=code;
    for(const p of waits.values())p.reject(new Error(code));
    waits.clear();
  };
  const send=msg=>{
    if(!child.stdin.writable)throw new Error('stdio-unavailable');
    child.stdin.write(JSON.stringify({jsonrpc:'2.0',...msg})+'\n');
  };
  child.stdin.on('error',()=>fail('stdio-unavailable'));
  child.once('error',()=>fail('process-start-error'));
  child.once('exit',()=>fail('process-ended'));
  const timer=setTimeout(()=>{fail('protocol-timeout');child.kill();},timeout);
  const cancelled=()=>{fail('provider-probe-aborted');child.kill();};
  signal?.addEventListener('abort',cancelled,{once:true});
  if(signal?.aborted)cancelled();
  child.stdout.on('data',chunk=>{
    if(fatal)return;
    total+=chunk.length;
    if(total>1048576){fail('protocol-size-limit');return;}
    buffer=Buffer.concat([buffer,chunk]);
    if(buffer.length>262144){fail('protocol-size-limit');return;}
    for(let ix;(ix=buffer.indexOf(10))>=0;) {
      const raw=buffer.subarray(0,ix);buffer=buffer.subarray(ix+1);
      let msg;
      try {
        msg=JSON.parse(raw.toString('utf8'));
        if(msg?.jsonrpc!=='2.0')throw new Error('protocol-error');
        if(typeof msg.method==='string') {
          if(Object.hasOwn(msg,'id')) {
            if(msg.method==='session/request_permission') {
              stage.permissionsDenied++;
              send({id:msg.id,result:{outcome:{outcome:'cancelled'}}});
            } else {
              stage.otherCallsDenied++;
              send({id:msg.id,error:{code:-32601,message:'Client capability unavailable'}});
            }
          } else if(msg.method==='session/update' && msg.params?.sessionId===sessionId) {
            const change=msg.params?.update;
            if(['tool_call','tool_call_update'].includes(change?.sessionUpdate))stage.toolUpdates++;
            if(change?.sessionUpdate==='agent_message_chunk' && change?.content?.type==='text' && typeof change.content.text==='string') {
              updates+=change.content.text;
              if(updates.length>512)throw new Error('protocol-error');
            }
          }
          continue;
        }
        const wait=waits.get(msg.id);
        if(!wait)throw new Error('protocol-error');
        waits.delete(msg.id);
        if(msg.error) {const e=new Error('rpc-error');e.rpc=msg.error.code;wait.reject(e);}
        else if(Object.hasOwn(msg,'result'))wait.resolve(msg.result);
        else {wait.reject(new Error('protocol-error'));fail('protocol-error');}
      }catch {fail('protocol-error');return;}
    }
  });
  const call=(method,params)=>new Promise((resolve,reject)=>{
    if(fatal){reject(new Error(fatal));return;}
    const id=++next;waits.set(id,{resolve,reject});
    try{send({id,method,params});}catch{fail('stdio-unavailable');}
  });
  let phase='initialize';
  try {
    const initialized=await call('initialize',{protocolVersion:1,clientCapabilities:{fs:{readTextFile:false,writeTextFile:false},terminal:false,auth:{terminal:false}},clientInfo:{name:'atomium',version:'0.3.0'}});
    if(initialized?.protocolVersion!==1)throw new Error('unsupported-protocol-version');
    stage.protocolVersion=1;
    stage.authMethods=Array.isArray(initialized.authMethods)?initialized.authMethods.length:0;
    phase='session/new';
    const session=await call(phase,{cwd,mcpServers:[]});
    if(typeof session?.sessionId!=='string'||!session.sessionId)throw new Error('session-id-invalid');
    sessionId=session.sessionId;stage.newSession=true;
    if(!prompt)return {status:'session-ready-prompt-not-authorized',...stage};
    phase='session/prompt';stage.promptSent=true;
    const result=await call(phase,{sessionId,prompt:[{type:'text',text:prompt}]});
    if(result?.stopReason!=='end_turn'||stage.permissionsDenied||stage.otherCallsDenied||stage.toolUpdates||!updates) return {status:'response-rejected',...stage};
    return {status:'response-ready',text:updates,...stage};
  } catch(e) {
    return {status:e.rpc===-32000?'auth-required':e.message,phase,...(Number.isInteger(e.rpc)?{rpcCode:e.rpc}:{}),...stage};
  }finally{
    clearTimeout(timer);
    signal?.removeEventListener('abort',cancelled);
    child.stdin.destroy();
    if(child.exitCode===null&&child.signalCode===null) await new Promise(ok=>{
      const limit=setTimeout(()=>{child.kill('SIGKILL');ok();},1000);
      child.once('exit',()=>{clearTimeout(limit);ok();});
      child.kill();
    });
  }
}

const installed=join(homedir(),'.local','bin','agy');
async function profileDirs(dir,create=false) {
  const names=['home','synthetic','tmp'];
  if(create)await mkdir(dir,{mode:0o700,recursive:true});
  if(await realpath(dir)!==dir)throw new Error('profile-must-not-be-symlink');
  const rootStat=await lstat(dir);
  if(!rootStat.isDirectory()||rootStat.uid!==process.getuid()||(rootStat.mode&0o077))throw new Error('profile-must-be-private');
  const result={};
  for(const name of names) {
    const path=join(dir,name);
    if(create)await mkdir(path,{mode:0o700,recursive:true});
    const st=await lstat(path);
    if(!st.isDirectory()||st.uid!==process.getuid()||(st.mode&0o077)||await realpath(path)!==path)throw new Error('profile-directory-must-be-private');
    result[name]=path;
  }
  return result;
}
function agyOptions(paths) {
  const {home,synthetic,tmp}=paths;
  return {
    command:installed,args:['acp','--stdio','--sandbox','--disable-telemetry','--include-default-customizations=false','--log-file',join(tmp,'agy.log')],
    cwd:synthetic,env:{HOME:home,TMPDIR:tmp,PATH:'/usr/bin:/bin',LANG:'C'},
  };
}
const deny = Object.freeze(['command(*)','read_file(*)','write_file(*)','read_url(*)','execute_url(*)','mcp(*)']);
const policy = {allowNonWorkspaceAccess:false,permissions:{allow:[],ask:[],deny}};
async function configurePolicy(home,create=false) {
  const dirs=[join(home,'.gemini'),join(home,'.gemini','antigravity-cli')];
  for(const dir of dirs) {
    if(create) await mkdir(dir,{recursive:true,mode:0o700});
    if(await realpath(dir)!==dir)throw new Error('policy-directory-symlink');
    const st=await lstat(dir);
    if(!st.isDirectory()||st.uid!==process.getuid()||(st.mode&0o077))throw new Error('policy-directory-not-private');
  }
  const path=join(dirs[1],'settings.json');
  if(create) {
    try { await lstat(path); }
    catch(e) {
      if(e.code!=='ENOENT')throw e;
      const tmp=await mkdtemp(join(dirs[1],'.policy-'));
      try {
        const staged=join(tmp,'settings.json');
        await writeFile(staged,JSON.stringify(policy,null,2)+'\n',{mode:0o600,flag:'wx'});
        await (await import('node:fs/promises')).link(staged,path);
      } finally { await rm(tmp,{recursive:true,force:true}); }
    }
  }
  const st=await lstat(path);
  if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o077)||await realpath(path)!==path||st.size>8192)throw new Error('policy-file-not-private');
  const current=JSON.parse(await readFile(path,'utf8'));
  if(JSON.stringify(current)!==JSON.stringify(policy))throw new Error('dedicated-policy-mismatch');
}
export async function agyDoctor() {
  const dir=await realpath(await mkdtemp(join(tmpdir(),'atomium-agy-')));
  try {
    return await acpConversation(agyOptions(await profileDirs(dir,true)));
  }finally {await rm(dir,{recursive:true,force:true});}
}
export async function dedicatedAgy(profile,prompt) {
  const gate=async d=>{const ss=await lstat(d);if(!ss.isDirectory()||ss.isSymbolicLink())throw new Error('profile-directory-unsafe');};
  await gate(profile);
  const paths=await profileDirs(profile);
  await configurePolicy(paths.home);
  // Create a different empty workspace for every prompt; never expose a real repo.
  const cwd=await mkdtemp(join(paths.synthetic,'run-'));
  try{return await acpConversation({...agyOptions(paths),cwd,prompt,timeout:90000,authorization:'user-dedicated-profile'});}
  finally{await rm(cwd,{recursive:true,force:true});}
}
async function officialLoginResult(profile,signal){
  if(!process.stdin.isTTY||!process.stdout.isTTY)throw new Error('Open your own Terminal for this step.');
  if(signal?.aborted)return {code:null,signal:'SIGINT'};
  const paths=await profileDirs(profile,true);
  const opts=agyOptions(paths);
  await configurePolicy(paths.home,true);
  if(signal?.aborted)return {code:null,signal:'SIGINT'};
  return new Promise((yes,no)=>{
    const child=spawn(opts.command,[...opts.args,'--login'],{cwd:opts.cwd,env:opts.env,stdio:'inherit'});
    let forced;
    const abort=()=>{
      if(child.exitCode!==null||child.signalCode!==null||forced)return;
      child.kill('SIGTERM');
      forced=setTimeout(()=>child.kill('SIGKILL'),1000);
    };
    const cleanup=()=>{clearTimeout(forced);signal?.removeEventListener('abort',abort);};
    child.once('error',error=>{cleanup();no(error);});
    child.once('exit',(code,observedSignal)=>{cleanup();yes({code,signal:signal?.aborted?'SIGINT':observedSignal});});
    signal?.addEventListener('abort',abort,{once:true});
    if(signal?.aborted)abort();
  });
}

// Preserve agy-auth's boolean return and existing explicit TTY guard.
export async function userLogin(profile){
  return (await officialLoginResult(profile)).code===0;
}

const authReceipt=(status,reason,protocolVersion=null)=>Object.freeze({
  provider:'agy',status,reason,protocolVersion,sessionReady:status==='ready',
  identityStatus:'identity-unavailable',identity:null,promptSent:false,
});
function sanitizeReadiness(result){
  const protocol=result?.protocolVersion===1?1:null;
  if(result?.promptSent!==false) return authReceipt('probe-failed','unexpected-prompt-status',protocol);
  if(result.status==='auth-required'&&result.rpcCode===-32000)
    return authReceipt('auth-required','provider-auth-required',protocol);
  if(result.status==='session-ready-prompt-not-authorized'&&protocol===1&&result.newSession===true&&
      result.permissionsDenied===0&&result.otherCallsDenied===0&&result.toolUpdates===0)
    return authReceipt('ready','official-acp-session-ready',protocol);
  return authReceipt('probe-failed','provider-session-unavailable',protocol);
}
function classifyLoginExit({code,signal}){
  if(code===0&&signal===null)return null;
  if(['SIGINT','SIGTERM','SIGHUP'].includes(signal)||[129,130,143].includes(code))
    return authReceipt('cancelled','official-login-cancelled');
  return authReceipt('login-failed','official-login-exited-nonzero');
}

/** Existing dedicated HOME only. Never sends a model prompt or reads auth tokens.
 * Official ACP v1 initializes and creates a session without reporting the
 * authenticated provider account. AgentInfo is a product/version record, not user identity.
 */
export async function probeAgyAuthentication(profileDir,{signal}={}){
  if(signal?.aborted)return authReceipt('cancelled','provider-probe-cancelled');
  if(typeof profileDir!=='string'||!profileDir||resolve(profileDir)!==profileDir)
    return authReceipt('probe-failed','profile-path-invalid');
  let dirs;
  try{dirs=await profileDirs(profileDir);}
  catch(e){
    return e.code==='ENOENT'?authReceipt('auth-required','profile-not-initialized'):
      authReceipt('probe-failed','profile-directory-unavailable');
  }
  try{await configurePolicy(dirs.home);}
  catch{return authReceipt('probe-failed','dedicated-policy-unavailable');}
  let scratch,receipt;
  try{
    scratch=await mkdtemp(join(dirs.synthetic,'auth-probe-'));
    const cwd=join(scratch,'cwd'),tmp=join(scratch,'tmp');
    await Promise.all([mkdir(cwd,{mode:0o700}),mkdir(tmp,{mode:0o700})]);
    receipt=sanitizeReadiness(await acpConversation({
      ...agyOptions({...dirs,synthetic:cwd,tmp}),timeout:8000,authorization:'user-dedicated-auth-probe',signal,
    }));
  }catch{receipt=authReceipt('probe-failed','provider-probe-unavailable');}
  if(scratch){
    try{await rm(scratch,{recursive:true,force:true});}
    catch{return authReceipt('probe-failed','probe-cleanup-incomplete');}
  }
  return signal?.aborted?authReceipt('cancelled','provider-probe-cancelled'):receipt;
}

/** Explicit user action from their Terminal; these tests never invoke the provider login. */
export async function runAgyProfileLogin(profileDir,{signal}={}){
  if(signal?.aborted)return authReceipt('cancelled','official-login-cancelled');
  if(!process.stdin.isTTY||!process.stdout.isTTY)return authReceipt('login-failed','interactive-terminal-required');
  if(typeof profileDir!=='string'||!profileDir||resolve(profileDir)!==profileDir)
    return authReceipt('login-failed','profile-path-invalid');
  let child;
  try{child=await officialLoginResult(profileDir,signal);}
  catch{return signal?.aborted?authReceipt('cancelled','official-login-cancelled'):authReceipt('login-failed','official-login-could-not-start');}
  return classifyLoginExit(child)??await probeAgyAuthentication(profileDir,{signal});
}

export async function verifyAgyLoginAdapter(){
  const raw={
    status:'session-ready-prompt-not-authorized',protocolVersion:1,newSession:true,promptSent:false,
    permissionsDenied:0,otherCallsDenied:0,toolUpdates:0,
    identity:'untrusted string',text:'untrusted model text',sessionId:'untrusted opaque session id',
  };
  const ready=sanitizeReadiness(raw);
  const dir=await mkdtemp(join(tmpdir(),'atomium-agy-abort-fixture-'));
  const control=new AbortController();
  const timer=setTimeout(()=>control.abort(),60);
  let cancelled;
  try{
    cancelled=await acpConversation({
      command:process.execPath,args:['-e','setInterval(()=>{},1000)'],env:{},cwd:dir,
      timeout:1500,authorization:'mock',signal:control.signal,
    });
  }finally{clearTimeout(timer);await rm(dir,{recursive:true,force:true});}
  return [
    {id:'agy-acp-ready-not-identity',pass:ready.status==='ready'&&ready.sessionReady&&ready.identityStatus==='identity-unavailable'&&ready.identity===null},
    {id:'agy-untrusted-identity-and-session-data-omitted',pass:!Object.values(ready).some(v=>typeof v==='string'&&v.startsWith('untrusted'))},
    {id:'agy-auth-required-distinct',pass:sanitizeReadiness({status:'auth-required',rpcCode:-32000,protocolVersion:1,promptSent:false}).status==='auth-required'},
    {id:'agy-probe-rejects-unexpected-prompt-or-tool',pass:sanitizeReadiness({...raw,promptSent:true}).status==='probe-failed'&&sanitizeReadiness({...raw,permissionsDenied:1}).status==='probe-failed'},
    {id:'agy-login-distinguishes-cancel-from-failure',pass:classifyLoginExit({code:130,signal:null}).status==='cancelled'&&classifyLoginExit({code:null,signal:'SIGINT'}).status==='cancelled'&&classifyLoginExit({code:1,signal:null}).status==='login-failed'&&classifyLoginExit({code:0,signal:null})===null},
    {id:'agy-probe-refuses-invalid-path-without-launch',pass:(await probeAgyAuthentication('relative-fixture')).reason==='profile-path-invalid'},
    {id:'agy-pre-aborted-actions-do-not-launch',pass:(await probeAgyAuthentication('/fixture-offline',{signal:AbortSignal.abort()})).status==='cancelled'&&(await runAgyProfileLogin('/fixture-offline',{signal:AbortSignal.abort()})).status==='cancelled'},
    {id:'agy-running-acp-mock-cancels-without-prompt',pass:cancelled.status==='provider-probe-aborted'&&cancelled.promptSent===false},
  ];
}

export async function verifyAcp() {
  const mock=String.raw`
    const {createInterface}=require('node:readline');
    const spy=process.argv[1];
    const ids=new Set();
    const out=m=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',...m})+'\n');
    const update=update=>out({method:'session/update',params:{sessionId:'synthetic',update}});
    createInterface({input:process.stdin}).on('line',line=>{
      const m=JSON.parse(line);
      if(m.method==='initialize'){
        if(m.params?.clientCapabilities?.terminal!==false||m.params?.clientCapabilities.fs.writeTextFile!==false)process.exit(5);
        out({id:m.id,result:{protocolVersion:1,authMethods:[]}});
      }else if(m.method==='session/new'){
        if(m.params.mcpServers.length)process.exit(6);
        out({id:m.id,result:{sessionId:'synthetic'}});
      }else if(m.method==='session/prompt'){
        if(spy==='blocked'){
          ids.add(m.id);
          out({id:901,method:'session/request_permission',params:{}});
          out({id:902,method:'fs/read_text_file',params:{path:'fixture-only'}});
          out({id:903,method:'terminal/create',params:{}});
          update({sessionUpdate:'tool_call'});
        }else{
          update({sessionUpdate:'agent_message_chunk',content:{type:'text',text:'{"view":'}});
          update({sessionUpdate:'agent_message_chunk',content:{type:'text',text:'"completed"}'}});
          out({id:m.id,result:{stopReason:'end_turn'}});
        }
      }else if(m.id===901&&m.result?.outcome?.outcome!=='cancelled') process.exit(1);
      else if((m.id===902||m.id===903)&&m.error?.code!==-32601)process.exit(2);
      else if(m.id===903){update({sessionUpdate:'agent_message_chunk',content:{type:'text',text:'{"view":"completed"}'}});out({id:[...ids][0],result:{stopReason:'end_turn'}});}
    });
  `;
  const cwd=await mkdtemp(join(tmpdir(),'atomium-acp-test-'));
  try {
    const r=await acpConversation({command:process.execPath,args:['-e',mock,'ok'],cwd,env:{},prompt:testPrompt,authorization:'mock'});
    if(r.status!=='response-ready'||r.text!=='{"view":"completed"}')throw new Error('mock valid ACP response failed');
    const b=await acpConversation({command:process.execPath,args:['-e',mock,'blocked'],cwd,env:{},prompt:testPrompt,authorization:'mock'});
    if(b.status!=='response-rejected'||b.permissionsDenied!==1||b.otherCallsDenied!==2||b.toolUpdates!==1)throw new Error('mock capability rejection failed');
    const {text,...stage}=r;
    return {text,stage,blocked:{status:b.status,permissionsDenied:b.permissionsDenied,otherCallsDenied:b.otherCallsDenied,toolUpdates:b.toolUpdates}};
  }finally{await rm(cwd,{recursive:true,force:true});}
}
