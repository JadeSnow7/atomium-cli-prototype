import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { lstat, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import { createServer, connect } from 'node:net';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const runs = fileURLToPath(new URL('./runs', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
const lit = path => '(literal ' + JSON.stringify(path) + ')';
const sub = path => '(subpath ' + JSON.stringify(path) + ')';

// Entire worker and its actions are fixed; never accept a user's command, path or host.
const worker = [
  "import { readFile, writeFile } from 'node:fs/promises';",
  "import { spawn } from 'node:child_process';",
  "import { connect, createServer } from 'node:net';",
  "const [,self,kind,a,b] = process.argv;",
  "const emit = s => console.log(s);",
  "const denied = e => ['EACCES','EPERM'].includes(e?.code);",
  "if (kind === 'files') {",
  "  if (await readFile('permitted.txt','utf8') === 'fixture') emit('fixture-read');",
  "  await writeFile('permitted-output.txt','fixture-output'); emit('fixture-write');",
  "  for (const [label,path] of [['outside',a],['peer',b]]) {",
  "    try { await readFile(path); emit(label+'-read-unexpected'); } catch(e) { emit(label+'-read-'+(denied(e)?'denied':'other')); }",
  "    try { await writeFile(path,'not-allowed'); emit(label+'-write-unexpected'); } catch(e) { emit(label+'-write-'+(denied(e)?'denied':'other')); }",
  "  }",
  "  emit(Object.hasOwn(process.env,'ATOMIUM_SYNTHETIC_CANARY')?'ambient-env-unexpected':'ambient-env-absent');",
  "} else if (kind === 'network') {",
  "  const s=connect({host:'127.0.0.1',port:Number(a)});",
  "  s.once('connect',()=>{emit('loopback-connect-unexpected');s.destroy();});",
  "  s.once('error',e=>emit(denied(e)?'loopback-connect-denied':'loopback-connect-other'));",
  "  s.setTimeout(1200,()=>{emit('loopback-connect-other');s.destroy();});",
  "  await new Promise(r=>s.once('close',r));",
  "  for (const ip of ['127.0.0.1','::1']) {",
  "    const server=createServer();",
  "    const result=await new Promise(r=>{server.once('error',e=>r(denied(e)?'denied':'other'));server.listen(0,ip,()=>server.close(()=>r('unexpected')));});",
  "    emit('bind-'+(ip==='::1'?'ipv6':'ipv4')+'-'+result);",
  "  }",
  "} else if (kind === 'tree-root') {",
  "  const child=spawn(process.execPath,[self,'tree-child'],{stdio:['ignore','pipe','ignore']});",
  "  child.stdout.once('data',data=>{if(String(data).trim()==='fixture-child-alive')emit('fixture-tree-alive');});",
  "  child.once('error',()=>emit('fixture-child-failed'));",
  "  setInterval(()=>{},1000);",
  "} else if (kind === 'tree-child') {",
  "  emit('fixture-child-alive'); setInterval(()=>{},1000);",
  "} else { process.exitCode=2; }",
].join('\n');

const expectedFiles = ['fixture-read','fixture-write','outside-read-denied','outside-write-denied','peer-read-denied','peer-write-denied','ambient-env-absent'];
const expectedNetwork = ['loopback-connect-denied','bind-ipv4-denied','bind-ipv6-denied'];
const lineAllow = new Set([...expectedFiles,...expectedNetwork,'fixture-tree-alive']);
const settled = (p, ms) => new Promise((resolve,reject)=>{
  const t=setTimeout(()=>reject(new Error('probe-timeout')),ms);
  p.then(x=>{clearTimeout(t);resolve(x);},e=>{clearTimeout(t);reject(e);});
});

export async function runBoundaryAudit() {
  if (process.platform!=='darwin') throw new Error('verify-boundary is macOS-only');
  await mkdir(runs,{recursive:true,mode:0o700});
  if (!(await lstat(runs)).isDirectory() || await realpath(runs)!==runs) throw new Error('unsafe-run-root');
  const run=await realpath(await mkdtemp(join(runs,'boundary-')));
  const task=join(run,'task'), peer=join(run,'peer'), outside=join(run,'outside');
  for (const dir of [task,peer,outside]) await mkdir(dir,{mode:0o700});
  const work=join(task,'probe.mjs'), marker='Atomium synthetic file marker';
  const outsideMarker=join(outside,'marker'), peerMarker=join(peer,'marker');
  for(const [p,content] of [[work,worker],[join(task,'permitted.txt'),'fixture'],[join(task,'openssl.cnf'),'# no inherited TLS config\n'],[outsideMarker,marker],[peerMarker,marker]]) {
    await writeFile(p,content,{flag:'wx',mode:0o600});
  }

  const executable=await realpath(process.execPath);
  const readonly=['/usr/lib','/System/Library','/Library/Apple/System/Library','/usr/share/icu','/private/var/db/timezone'];
  const dylib=' (regex #"^/opt/homebrew/Cellar/[^/]+/[^/]+/lib/.*[.]dylib$") (regex #"^/opt/homebrew/opt/[^/]+/lib/.*[.]dylib$")';
  const profile=[
    '(version 1)','(deny default)','(allow process-exec '+lit(executable)+')','(allow process-fork)',
    '(allow signal (target self))','(allow ipc-posix-sem*)','(allow sysctl-read)','(allow file-read-metadata)',
    '(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.notification_center"))',
    '(allow file-read-data '+[task,...readonly].map(sub).join(' ')+' '+['/',executable,'/dev/null','/dev/urandom'].map(lit).join(' ')+dylib+')',
    '(allow file-map-executable '+[...readonly,'/opt/homebrew/Cellar','/opt/homebrew/opt'].map(sub).join(' ')+' '+lit(executable)+')',
    '(allow file-write* '+sub(task)+' '+lit('/dev/null')+')',
  ].join('\n');

  const checks=[];
  const add=(id,pass,details={})=>{
    checks.push({id,pass:Boolean(pass),...details});
    console.log((pass?'PASS ':'FAIL ')+id);
  };
  const env={HOME:task,TMPDIR:task,PATH:'/usr/bin:/bin',LANG:'C',OPENSSL_CONF:join(task,'openssl.cnf')};
  function launch(args) {
    const p=spawn('/usr/bin/sandbox-exec',['-p',profile,executable,work,...args],{cwd:task,env,detached:true,stdio:['ignore','pipe','ignore']});
    let stdout='', invalid=false;
    p.stdout.on('data',data=>{if(stdout.length+data.length>4096){invalid=true;return;}stdout+=data;});
    const ended=once(p,'close');
    ended.catch(()=>{}); // observed below; keep an early spawn error bounded
    const groupSignal=sig=>{
      if(!Number.isInteger(p.pid) || p.pid<2) return false;
      try{process.kill(-p.pid,sig);return true;}catch(e){if(e.code==='ESRCH')return false;throw e;}
    };
    return {p,ended,groupSignal,lines:()=>invalid?null:stdout.trim().split('\n').filter(Boolean).map(l=>lineAllow.has(l)?l:'unrecognized')};
  }

  async function runOne(args) {
    const p=launch(args);
    try{
      const [exitCode]=await settled(p.ended,5000);
      return {exitCode,lines:p.lines()};
    }catch{
      p.groupSignal('SIGKILL');
      await settled(p.ended.catch(()=>null),2000).catch(()=>null);
      return {exitCode:null,lines:null};
    }
  }
  // Demonstrate an ambient marker exists at the controller, then omit it from worker env.
  const markerName='ATOMIUM_SYNTHETIC_CANARY';
  const old=process.env[markerName];
  let files;
  try {
    process.env[markerName]='fake-canary-not-a-credential';
    files=await runOne(['files',outsideMarker,peerMarker]);
  }finally{if(old===undefined)delete process.env[markerName];else process.env[markerName]=old;}
  const lines=files.lines??[];
  let wrote=false;
  try{wrote=await readFile(join(task,'permitted-output.txt'),'utf8')==='fixture-output';}catch{}
  add('workspace-positive-control',files.exitCode===0&&lines[0]==='fixture-read'&&lines[1]==='fixture-write'&&wrote);
  add('outside-and-peer-file-isolation',files.exitCode===0&&expectedFiles.slice(2,6).every(x=>lines.includes(x))&&await readFile(outsideMarker,'utf8')===marker&&await readFile(peerMarker,'utf8')===marker);
  add('ambient-environment-not-inherited',files.exitCode===0&&lines.length===expectedFiles.length&&lines.every((line,i)=>line===expectedFiles[i]));

  const listener=createServer(socket=>{hits++;socket.end();});
  let hits=0;
  try {
    listener.listen(0,'127.0.0.1');
    await settled(once(listener,'listening'),2500);
    const port=listener.address().port;
    const control=connect({host:'127.0.0.1',port});
    try{await settled(once(control,'end'),2500);}finally{control.destroy();}
    const before=hits;
    const net=await runOne(['network',String(port)]);
    add('isolated-worker-loopback',before===1&&hits===before&&net.exitCode===0&&net.lines?.includes(expectedNetwork[0]),{controlConnections:before,workerConnections:hits-before});
    add('isolated-worker-listen-ipv4-ipv6',net.exitCode===0&&expectedNetwork.slice(1).every(x=>net.lines?.includes(x)));
  }catch{
    add('isolated-worker-loopback',false,{reason:'control-unavailable'});
    add('isolated-worker-listen-ipv4-ipv6',false,{reason:'control-unavailable'});
  }finally{if(listener.listening)await new Promise(r=>listener.close(r));}

  const group=launch(['tree-root']);
  let ready=false,groupGone=false;
  try{
    for(let i=0;i<60;i++){
      if(group.lines()?.includes('fixture-tree-alive')){ready=true;break;}
      if(group.p.exitCode!==null || group.p.signalCode!==null)break;
      await new Promise(r=>setTimeout(r,40));
    }
    if(ready){
      const signalled=group.groupSignal('SIGTERM');
      const ended=await settled(group.ended,2000);
      if(signalled&&ended[1]==='SIGTERM'){
        for(let i=0;i<30;i++){
          if(!group.groupSignal(0)){groupGone=true;break;}
          await new Promise(r=>setTimeout(r,40));
        }
      }
    }
  }catch{}finally{
    if(!groupGone)group.groupSignal('SIGKILL');
    await settled(group.ended.catch(()=>null),2000).catch(()=>null);
  }
  add('cancel-fixed-worker-process-group',ready&&groupGone,{childReady:ready,groupGone});

  const report={version:1,scope:'fixed offline Node boundary fixture only',profileSha256:hash(profile),checks,uncovered:[
    'native Swift policies are verified separately','host-side Gemini/Codex process and credentials','provider tool enforcement and cancellation',
    'external network, model gateway and DLP','arbitrary repository and process-tree scenarios','browser isolation','receipt issuer authenticity',
  ],approved:false,exported:false};
  await writeFile(join(run,'evidence.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log('Evidence: '+join(run,'evidence.json'));
  return checks.every(x=>x.pass);
}
