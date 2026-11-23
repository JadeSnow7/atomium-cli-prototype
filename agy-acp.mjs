import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,rm,lstat,realpath,readFile,writeFile,rename} from 'node:fs/promises';
import {homedir,tmpdir} from 'node:os';
import {join,resolve} from 'node:path';

const testPrompt = 'Atomium synthetic fixture. Select a JSON view for checked-off tasks only.';
export async function acpConversation({command,args,env,cwd,prompt,timeout=8000,authorization='clean-home-no-auth'}) {
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
export async function userLogin(profile){
  if(!process.stdin.isTTY||!process.stdout.isTTY)throw new Error('Open your own Terminal for this step.');
  const paths=await profileDirs(profile,true);
  const opts=agyOptions(paths);
  await configurePolicy(paths.home,true);
  const code=await new Promise((yes,no)=>{
    const child=spawn(opts.command,[...opts.args,'--login'],{cwd:opts.cwd,env:opts.env,stdio:'inherit'});
    child.once('error',no);child.once('exit',yes);
  });
  return code===0;
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
