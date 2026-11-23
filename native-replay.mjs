import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,mkdtemp,open,writeFile,realpath,lstat,symlink} from 'node:fs/promises';
import {constants as fsFlags} from 'node:fs';
import {join,dirname,basename,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline/promises';

const execute=promisify(execFile);
const sha=x=>createHash('sha256').update(x).digest('hex');
const stable=x=>JSON.stringify(x);
const limits=Object.freeze({receipt:32768,source:65536,binary:16*1024*1024,compiler:256*1024*1024});
const boundary=Object.freeze({
  policy:'macos-native-p0-v1',frozenInput:'exact source, read-only in compiler',
  compiler:'fixed toolchain, writes only to scratch plus /dev/null, no allowed network',
  runtime:'exact executable, no allowed file writes or network',
  stdout:'closed fixture tokens; unexpected output suppressed',
  notCovered:['managed model egress/DLP','browser isolation','provider descendants','same-account hostile artifact issuer'],
});
async function readFixed(path,limit) {
  if(await realpath(path)!==path)throw new Error('unsafe-replay-input');
  const handle=await open(path,fsFlags.O_RDONLY|fsFlags.O_NOFOLLOW|fsFlags.O_NONBLOCK);
  try{
    const st=await handle.stat();
    if(!st.isFile()||st.size<1||st.size>limit||st.nlink!==1)throw new Error('bounded-input-invalid');
    const bytes=Buffer.alloc(st.size+1);
    let count=0;
    while(count<bytes.length){
      const {bytesRead}=await handle.read(bytes,count,bytes.length-count,count);
      if(!bytesRead)break;
      count+=bytesRead;
    }
    const after=await handle.stat();
    if(count!==st.size||after.size!==st.size||after.mtimeMs!==st.mtimeMs||after.ctimeMs!==st.ctimeMs)throw new Error('bounded-input-changed');
    return bytes.subarray(0,count);
  }finally{await handle.close();}
}
const root=resolve(fileURLToPath(new URL('.',import.meta.url)));
const runs=join(root,'runs');
const spec={
  id:'atomium-native-draft-v2',
  rule:'Names are equal only if their UTF-8 bytes exactly match. A duplicate may be saved as a draft, but formal submit must reject it without changing draft status. After renaming to a unique name it may be formally submitted.',
  boundary:'No case folding, whitespace trimming, or Unicode normalization.'
};
const specSha=sha(stable(spec));
const baseSource=[
  'let args = Array(CommandLine.arguments.dropFirst())',
  'func equalName(_ left: String, _ right: String) -> Bool {',
  '    return false // ATOMIUM_NAME_RULE',
  '}',
  'if args.first == "version" && args.count == 1 { print("Atomium Native Draft v2"); }',
  'else if args.count >= 3 {',
  '    let occupied = args[0]',
  '    var name = args[1]',
  '    var state = "unsaved"',
  '    for action in args.dropFirst(2) {',
  '        if action == "show" { print("state:" + state) }',
  '        else if action == "save" && state == "unsaved" {',
  '            state = "draft"; print("saved:draft")',
  '        } else if action == "submit" && state == "draft" {',
  '            if equalName(name, occupied) { print("duplicate:draft") }',
  '            else { state = "submitted"; print("submitted:submitted") }',
  '        } else if action.utf8.starts(with: "rename:".utf8) && state == "draft" {',
  '            name = String(decoding: action.utf8.dropFirst(7), as: UTF8.self); print("renamed:draft")',
  '        } else if action == "reset" {',
  '            state = "unsaved"; name = args[1]; print("reset:unsaved")',
  '        } else { print("not-allowed:" + state) }',
  '    }',
  '} else { print("usage") }',
].join('\n')+'\n';
const baselineLine='return false // ATOMIUM_NAME_RULE';
const edits=Object.freeze({
  'exact-raw-name':'return left.utf8.elementsEqual(right.utf8) // ATOMIUM_NAME_RULE',
  'folded-name':'return left.lowercased() == right.lowercased() // ATOMIUM_NAME_RULE',
});
const t=Object.freeze([
  ['build-identifies-app',['version'],['Atomium Native Draft v2']],
  ['duplicate-saves-draft',['Aster','Aster','save','show'],['saved:draft','state:draft']],
  ['duplicate-submit-rejected-keeps-draft',['Aster','Aster','save','submit','show'],['saved:draft','duplicate:draft','state:draft']],
  ['rename-unique-then-submits',['Aster','Aster','save','submit','rename:Birch','submit','show'],['saved:draft','duplicate:draft','renamed:draft','submitted:submitted','state:submitted']],
  ['case-distinct',['Aster','aster','save','submit','show'],['saved:draft','submitted:submitted','state:submitted']],
  ['whitespace-distinct',['Aster','Aster ','save','submit'],['saved:draft','submitted:submitted']],
  ['unicode-sequences-distinct',['\u00e9','e\u0301','save','submit'],['saved:draft','submitted:submitted']],
  ['rename-preserves-leading-combining-mark',['\u0301A','Aster','save','rename:\u0301A','submit','show'],['saved:draft','renamed:draft','duplicate:draft','state:draft']],
  ['reset-restores-fixture',['Aster','Aster','save','reset','show','save','submit','show'],['saved:draft','reset:unsaved','state:unsaved','saved:draft','duplicate:draft','state:draft']],
]);
const suiteSha=sha(stable(t));
function materialize(rule) {
  if(!Object.hasOwn(edits,rule)||baseSource.split(baselineLine).length!==2)throw new Error('source-edit-not-allowed');
  return baseSource.replace(baselineLine,edits[rule]);
}
async function fresh(prefix) {
  await mkdir(runs,{mode:0o700,recursive:true});
  if(!(await lstat(runs)).isDirectory()||await realpath(runs)!==runs)throw new Error('run-directory-invalid');
  return mkdtemp(join(runs,prefix));
}
async function outputAt(run,report) {
  await writeFile(join(run,'evidence.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log('Evidence: '+join(run,'evidence.json'));
}
function literal(p) {return '(literal '+stable(p)+')';}
function sub(p) {return '(subpath '+stable(p)+')';}
async function toolchain() {
  if(process.platform!=='darwin')throw new Error('macOS-host-required');
  const toolsEnv={PATH:'/usr/bin:/bin',LANG:'C'};
  const developer=await realpath((await execute('/usr/bin/xcode-select',['-p'],{env:toolsEnv,timeout:6000})).stdout.trim());
  const compiler=(await execute('/usr/bin/xcrun',['--find','swiftc'],{env:toolsEnv,timeout:6000})).stdout.trim();
  if(!compiler.startsWith(developer+'/Toolchains/')||basename(compiler)!=='swiftc')throw new Error('unexpected-xcode-swift-toolchain');
  const version=(await execute(compiler,['--version'],{env:toolsEnv,timeout:6000})).stdout.trim();
  const sdk=join(developer,'Platforms','MacOSX.platform','Developer','SDKs','MacOSX.sdk');
  const bin=dirname(compiler);
  const commands=['swiftc','swift-driver','swift-frontend','clang','ld','ld-classic'].map(name=>join(bin,name));
  const compilerSha=sha(await readFixed(await realpath(compiler),limits.compiler));
  return {developer,compiler,version,sdk,bin,commands,compilerSha};
}
function restricted({binary,tools,source,scratch}) {
  const system=['/System/Library','/usr/lib'];
  const readonly=tools?[...system,tools.developer,join(dirname(tools.developer),'SharedFrameworks')]:system;
  const allowed=tools?[sub(scratch),literal(source)]:[literal(binary)];
  const maps=tools?[sub(scratch)]:[literal(binary)];
  const commands=tools?tools.commands:[binary];
  return [
    '(version 1)(deny default)(allow signal (target self))(allow ipc-posix-sem*)(allow sysctl-read)(allow file-read-metadata)',
    ...(tools?['(allow process-fork)']:[]),
    '(allow file-read-data '+[...allowed,...readonly.map(sub),...['/','/dev/null','/dev/urandom'].map(literal)].join(' ')+')',
    '(allow file-map-executable '+[...maps,...readonly.map(sub)].join(' ')+')',
    '(allow process-exec '+commands.map(literal).join(' ')+')',
    ...(tools?['(allow file-write* '+sub(scratch)+' '+literal('/dev/null')+')']:[]),
  ].join('\n');
}
const safeLines=new Set(t.flatMap(([, ,expected])=>expected).concat([
  'not-allowed:unsaved','not-allowed:draft','not-allowed:submitted','usage',
]));
function cleanFixtureOutput(raw) {
  if(typeof raw!=='string'||raw.length>1024||!raw.endsWith('\n'))return null;
  const lines=raw.slice(0,-1).split('\n');
  return lines.length<=24&&lines.every(line=>safeLines.has(line))?lines:null;
}
async function inSandbox(task,profile,command,args,timeout=8000,toolPath='',expectedWriteDenial) {
  const env={HOME:task,TMPDIR:task,PATH:toolPath?toolPath+':/usr/bin:/bin':'/usr/bin:/bin',LANG:'C'};
  try {
    const result=await execute('/usr/bin/sandbox-exec',['-p',profile,command,...args],{cwd:task,env,timeout,maxBuffer:65536});
    return {ok:true,stdout:result.stdout};
  } catch(e) {
    const why=String(e.stderr??'');
    if(expectedWriteDenial&&why.split('\n').includes("ld: can't write output file: "+expectedWriteDenial))
      return {ok:false,error:'expected-linker-output-write-denial',exitCode:Number.isInteger(e.code)?e.code:null};
    return {ok:false,error:why.includes('sandbox_apply')?'nested-sandbox-denied':/Operation not permitted|Permission denied|errno=1\b/.test(why)?'sandbox-operation-denied':'sandboxed-command-failed',exitCode:Number.isInteger(e.code)?e.code:null,signal:e.signal??null};
  }
}
async function probeNativePolicies() {
  const run=await fresh('native-boundary-'), task=join(run,'task'), scratch=join(task,'compiler-scratch'), cache=join(scratch,'cache');
  await mkdir(cache,{recursive:true,mode:0o700});
  const tools=await toolchain();
  const source=join(task,'probe.swift'), staged=join(scratch,'probe'), binary=join(task,'probe');
  const sentinel=join(run,'synthetic-sibling');
  await writeFile(sentinel,'SYNTHETIC_ONLY',{mode:0o600,flag:'wx'});
  const before=sha(await readFixed(sentinel,limits.source));
  await writeFile(source,[
    'import Darwin',
    'let path = CommandLine.arguments[1]',
    'func probe(_ flags: Int32) -> Bool {',
    '    let fd = open(path, flags)',
    '    if fd >= 0 { close(fd); return false }',
    '    return errno == EPERM || errno == EACCES',
    '}',
    'print(probe(O_RDONLY) ? "READ_DENIED" : "READ_NOT_DENIED")',
    'print(probe(O_WRONLY) ? "WRITE_DENIED" : "WRITE_NOT_DENIED")',
    'print(getenv("ATOMIUM_SYNTHETIC_FAKE_ENV") == nil ? "ENV_ABSENT" : "ENV_PRESENT")',
  ].join('\n')+'\n',{mode:0o400,flag:'wx'});
  const cprof=restricted({binary,source,scratch,tools});
  const compile=(output,expectedDenial)=>inSandbox(scratch,cprof,tools.compiler,['-sdk',tools.sdk,'-module-cache-path',cache,source,'-o',output],35000,tools.bin,expectedDenial);
  // Both destinations start as regular 0600 sentinel files with identical bytes.
  await writeFile(staged,'SYNTHETIC_ONLY',{mode:0o600,flag:'wx'});
  const scratchInitiallySame=sha(await readFixed(staged,limits.source))===before;
  const allowed=await compile(staged);
  if(!allowed.ok)throw new Error('native-policy-probe-control-build-failed:'+allowed.error);
  const denied=await compile(sentinel,sentinel);
  await writeFile(binary,await readFixed(staged,limits.binary),{mode:0o500,flag:'wx'});
  const runtime=restricted({binary});
  const previous=process.env.ATOMIUM_SYNTHETIC_FAKE_ENV;
  process.env.ATOMIUM_SYNTHETIC_FAKE_ENV='SYNTHETIC_VALUE_ONLY';
  let result;
  try{result=await inSandbox(task,runtime,binary,[sentinel]);}
  finally{if(previous===undefined)delete process.env.ATOMIUM_SYNTHETIC_FAKE_ENV;else process.env.ATOMIUM_SYNTHETIC_FAKE_ENV=previous;}
  const labels=result.ok?result.stdout.split('\n'):[];
  const unchanged=sha(await readFixed(sentinel,limits.source))===before;
  const checks={
    compilerScratchControl:allowed.ok&&scratchInitiallySame&&sha(await readFixed(staged,limits.binary))!==before,
    compilerSiblingWriteDenied:!denied.ok&&denied.error==='expected-linker-output-write-denial',
    siblingUnchanged:unchanged,
    runtimeSiblingReadDenied:labels[0]==='READ_DENIED',
    runtimeSiblingWriteDenied:labels[1]==='WRITE_DENIED',
    syntheticParentEnvAbsent:labels[2]==='ENV_ABSENT',
  };
  await outputAt(run,{version:1,mode:'trusted-native-boundary-probe',boundary,checks,compilerResult:denied.ok?'unexpected-allowed':denied.error,runtimeResult:result.ok?'executed':result.error});
  if(!Object.values(checks).every(Boolean))throw new Error('native-policy-probe-failed');
  console.log('PASS fixed-native-compiler-runtime-policy-probe');
}
async function appSuite(task,binary) {
  const profile=restricted({binary});
  const checks=[];
  for(const [id,args,expected] of t){
    const observation=await inSandbox(task,profile,binary,args);
    const actual=observation.ok?cleanFixtureOutput(observation.stdout):null;
    const pass=actual!==null&&stable(actual)===stable(expected);
    checks.push({id,pass,expected,actual,...(actual===null?{error:observation.ok?'unexpected-stdout-suppressed':observation.error}:{})});
    console.log((pass?'PASS ':'FAIL ')+id);
  }
  return {runtimeProfileSha:sha(profile),checks};
}
function candidateManifest(rule) {
  const proposed=materialize(rule);
  const manifest=stable({spec,specSha,suiteSha,baselineSource:baseSource,baselineSourceSha:sha(baseSource),candidateSource:proposed,candidateSourceSha:sha(proposed)});
  return {rule,proposed,manifest,manifestSha:sha(manifest),sourceSha:sha(proposed)};
}
async function reviewNative(candidate,ask) {
  const expected=candidate.manifestSha;
  const prompt='Review only the candidate Swift source against the stated synthetic business rule. The baseline is intentionally faulty and supplied only for comparison. This is a narrow CLI fixture, not a production submit system. No tools. Predict what the candidate prints for the formal submit step after a successful save, for these three independent inputs: duplicate = occupied Aster / draft Aster; caseVariant = occupied Aster / draft aster; unicodeVariant = occupied U+00E9 / draft U+0065 U+0301. For each prediction choose duplicate:draft or submitted:submitted. Then decide whether the candidate meets the stated rule, including keeping draft on a rejected submit and allowing a later unique rename. Return a JSON object ONLY, keys in this order: verdict (accept or reject), manifestSha256 (paste supplied SHA), duplicate, caseVariant, unicodeVariant. Frozen manifest SHA-256: '+expected+'\nFrozen manifest: '+candidate.manifest;
  let text;
  try {text=await ask(prompt);}catch{return {source:'codex-host',status:'review-provider-unavailable'};}
  const replies='(duplicate:draft|submitted:submitted)';
  const format=new RegExp('^\\s*\\{\\s*"verdict"\\s*:\\s*"(accept|reject)"\\s*,\\s*"manifestSha256"\\s*:\\s*"[a-f0-9]{64}"\\s*,\\s*"duplicate"\\s*:\\s*"'+replies+'"\\s*,\\s*"caseVariant"\\s*:\\s*"'+replies+'"\\s*,\\s*"unicodeVariant"\\s*:\\s*"'+replies+'"\\s*\\}\\s*$');
  if(typeof text!=='string'||text.length>350||!format.test(text))return {source:'codex-host',status:'review-schema-rejected'};
  let m;
  try {m=JSON.parse(text);}catch{return {source:'codex-host',status:'review-schema-rejected'};}
  const observed={duplicate:m.duplicate,caseVariant:m.caseVariant,unicodeVariant:m.unicodeVariant};
  const expectedObservations={duplicate:'duplicate:draft',caseVariant:'submitted:submitted',unicodeVariant:'submitted:submitted'};
  const status=m.manifestSha256!==expected?'review-binding-mismatch':m.verdict!=='accept'?'review-rejected':stable(observed)!==stable(expectedObservations)?'review-observation-mismatch':'accepted';
  return {source:'codex-host',status,verdict:m.verdict,manifestSha:m.manifestSha256,observed};
}
async function buildPair(mode,ask,propose) {
  const run=await fresh('native-');
  let proposal={source:mode==='native-live'?'agy-acp-host':'trusted-self-test',status:mode==='native-live'?'pending':'accepted',rule:mode==='native-wrong'?'folded-name':'exact-raw-name'};
  let review=null;
  const fail=async(status,more={})=>{
    console.error('STOP '+status+'; no approved delivery.');
    await outputAt(run,{version:1,boundary,mode,status,specSha,suiteSha,proposal,review,approval:null,exported:false,...more});
    return {run,status};
  };
  if(mode==='native-live'){
    let result;
    try {result=await propose('No tools. For the supplied business rule, select one narrow name comparison implementation. Reply solely as a JSON object with the single field rule, using one of exact-raw-name, folded-name, none. Human rule: '+spec.rule+' '+spec.boundary);}
    catch {return fail('proposal-provider-unavailable');}
    const {text,...stage}=result;
    proposal={...proposal,acp:stage};
    if(stage.status!=='response-ready')return fail('proposal-provider-unavailable');
    if(typeof text!=='string'||!/^\s*\{\s*"rule"\s*:\s*"exact-raw-name"\s*\}\s*$/.test(text)||text.length>100)return fail('proposal-contract-rejected');
    proposal.status='accepted';
  }
  const c=candidateManifest(proposal.rule);
  await writeFile(join(run,'review-manifest.json'),c.manifest,{mode:0o600,flag:'wx'});
  if(mode==='native-live'){
    review=await reviewNative(c,ask);
    if(review.status!=='accepted')return fail(review.status,{manifestSha:c.manifestSha,sourceSha:c.sourceSha});
  }
  const task=join(run,'task');
  await mkdir(task,{mode:0o700});
  const source=join(task,'main.swift'),binary=join(task,'app');
  await writeFile(source,c.proposed,{mode:0o400,flag:'wx'});
  if(sha(await readFixed(source,limits.source))!==c.sourceSha)return fail('source-binding-mismatch');
  const tools=await toolchain();
  const scratch=join(task,'compiler-scratch'),cache=join(scratch,'cache'),staged=join(scratch,'app');
  await mkdir(scratch,{mode:0o700});
  await mkdir(cache,{mode:0o700});
  const profile=restricted({binary,source,scratch,tools});
  const result=await inSandbox(scratch,profile,tools.compiler,['-sdk',tools.sdk,'-module-cache-path',cache,source,'-o',staged],35000,tools.bin);
  if(!result.ok)return fail('swift-compile-failed',{build:result});
  const artifact=await readFixed(staged,limits.binary);
  await writeFile(binary,artifact,{mode:0o500,flag:'wx'});
  if(sha(await readFixed(source,limits.source))!==c.sourceSha)return fail('post-build-source-binding-mismatch');
  const buildSha=sha(await readFixed(binary,limits.binary));
  const build={sourceSha:c.sourceSha,buildSha,profileSha:sha(profile),toolchain:tools.version,compilerSha:tools.compilerSha};
  const {runtimeProfileSha,checks}=await appSuite(task,binary);
  const green=checks.every(c=>c.pass);
  if(!green)return fail('behavior-rejected',{build,checks,runtimeProfileSha,manifestSha:c.manifestSha,sourceSha:c.sourceSha});
  if(sha(await readFixed(binary,limits.binary))!==buildSha||sha(await readFixed(source,limits.source))!==c.sourceSha)return fail('post-test-build-binding-mismatch');
  let kind=null;
  const binding={fixtureId:spec.id,specSha,suiteSha,rule:c.rule,sourceSha:c.sourceSha,buildSha,manifestSha:c.manifestSha};
  if(mode==='native-self-test')kind='self-test-only';
  else if(mode==='native-live'&&process.stdin.isTTY&&process.stdout.isTTY) {
    console.log('Exact approval candidate '+stable(binding));
    const ui=createInterface({input:process.stdin,output:process.stdout});
    try{if((await ui.question('Approve this exact synthetic executable for offline replay? Type yes (default deny): ')).trim()==='yes')kind='interactive';}
    finally{ui.close();}
  }
  const approval=kind?{kind,binding,receiptSha:sha(stable({kind,binding}))}:null;
  const status=approval?'replay-authorized':'verified-not-approved';
  await outputAt(run,{version:1,boundary,mode,status,specSha,suiteSha,proposal,review,manifestSha:c.manifestSha,sourceSha:c.sourceSha,build,checks,runtimeProfileSha,approval,exported:false});
  console.log(status+' build '+buildSha);
  return {run,status};
}

async function verifiedReceipt(raw,allowTest) {
  if(!raw)throw new Error('receipt-path-required');
  const path=resolve(raw);
  const run=dirname(path);
  if(basename(path)!=='evidence.json'||dirname(run)!==runs||!/^native-[a-zA-Z0-9]+$/.test(basename(run))||await realpath(path)!==path)throw new Error('receipt-is-not-an-Atomium-native-run');
  const r=JSON.parse((await readFixed(path,limits.receipt)).toString('utf8'));
  const kind=r.approval?.kind;
  if(kind!=='interactive'&&!(allowTest&&kind==='self-test-only'))throw new Error('exact-candidate-not-approved');
  if(r.version!==1||r.status!=='replay-authorized'||r.specSha!==specSha||r.suiteSha!==suiteSha||r.proposal?.rule!=='exact-raw-name'||r.checks?.length!==t.length||r.checks.some((check,i)=>!check.pass||check.id!==t[i][0]))throw new Error('receipt-contract-mismatch');
  const c=candidateManifest('exact-raw-name');
  const boundApproval=(kind==='interactive'&&r.mode==='native-live'&&r.proposal.source==='agy-acp-host'&&r.proposal.status==='accepted'&&r.review?.verdict==='accept'&&r.review.status==='accepted'&&r.review.manifestSha===c.manifestSha)
    || (kind==='self-test-only'&&r.mode==='native-self-test'&&r.proposal.source==='trusted-self-test');
  if(!boundApproval)throw new Error('approval-mode-binding-mismatch');
  const manifestPath=join(run,'review-manifest.json'),src=join(run,'task','main.swift'),bin=join(run,'task','app');
  if(sha(await readFixed(manifestPath,limits.source))!==c.manifestSha||sha(await readFixed(src,limits.source))!==c.sourceSha)throw new Error('frozen-candidate-tampered');
  const bytes=await readFixed(bin,limits.binary);
  const buildSha=sha(bytes);
  const binding={fixtureId:spec.id,specSha,suiteSha,rule:c.rule,sourceSha:c.sourceSha,buildSha,manifestSha:c.manifestSha};
  if(r.build?.buildSha!==buildSha||r.build.sourceSha!==c.sourceSha||stable(r.approval.binding)!==stable(binding)||r.approval.receiptSha!==sha(stable({kind,binding})))throw new Error('replay-binary-or-approval-mismatch');
  return {bytes,binding,kind,path};
}
async function replayRun(receipt,allowTest,appArgs) {
  const reviewed=await verifiedReceipt(receipt,allowTest);
  const run=await fresh('replay-');
  const task=join(run,'task'),binary=join(task,'app');
  await mkdir(task,{mode:0o700});
  await writeFile(binary,reviewed.bytes,{mode:0o500,flag:'wx'});
  if(sha(await readFixed(binary,limits.binary))!==reviewed.binding.buildSha)throw new Error('replay-copy-binding-mismatch');
  if(appArgs){
    const okay=appArgs.length===1&&appArgs[0]==='version'||appArgs.length>=3&&appArgs.length<=24&&appArgs.every(x=>x.length<=64&&!/[\x00-\x1f\x7f]/.test(x))&&appArgs.slice(2).every(x=>['show','save','submit','reset'].includes(x)||/^rename:.{1,50}$/.test(x));
    if(!okay)throw new Error('fixture-input-invalid; use version or occupiedName draftName actions: show save submit rename:NAME reset');
    const result=await inSandbox(task,restricted({binary}),binary,appArgs);
    if(!result.ok)throw new Error(result.error);
    const parsed=cleanFixtureOutput(result.stdout);
    if(parsed===null)throw new Error('unexpected-stdout-suppressed');
    console.log(parsed.join('\n'));
    return;
  }
  const {runtimeProfileSha,checks}=await appSuite(task,binary);
  const passed=checks.every(x=>x.pass)&&sha(await readFixed(binary,limits.binary))===reviewed.binding.buildSha;
  await outputAt(run,{version:1,boundary,mode:'replay',sourceApproval:reviewed.kind,binding:reviewed.binding,runtimeProfileSha,checks,passed,usedModel:false});
  if(!passed)process.exitCode=1;
}
export async function nativeMain(cmd,args,{askCodex,proposeAgy}) {
  if(cmd==='native-live'&&args.length===0){const r=await buildPair(cmd,askCodex,proposeAgy);if(!['verified-not-approved','replay-authorized'].includes(r.status))process.exitCode=1;return;}
  if(cmd==='verify-native'&&args.length===0){
    for(const bad of ['synthetic-secret-not-a-fixture-token\n','saved:draft\nsynthetic-secret\n','saved:draft\x1b\n','saved:draft\n\n']){
      if(cleanFixtureOutput(bad)!==null)throw new Error('unknown-stdout-was-allowed');
    }
    if(stable(cleanFixtureOutput('saved:draft\nstate:draft\n'))!==stable(['saved:draft','state:draft']))throw new Error('known-stdout-was-blocked');
    console.log('PASS native-stdout-closed-token-gate');
    await probeNativePolicies();
    const yes=await buildPair('native-self-test');
    if(yes.status!=='replay-authorized')throw new Error('correct fixture failed');
    const no=await buildPair('native-wrong');
    if(no.status!=='behavior-rejected')throw new Error('deliberate wrong fixture was not behavior-rejected');
    try{await verifiedReceipt(join(no.run,'evidence.json'),true);throw new Error('wrong-run-replay-was-accepted');}
    catch(e){if(e.message!=='exact-candidate-not-approved')throw e;}
    try{await verifiedReceipt(join(yes.run,'evidence.json'),false);throw new Error('self-test-receipt-accepted-without-flag');}
    catch(e){if(e.message!=='exact-candidate-not-approved')throw e;}
    // Copy only the synthetic run, then change one byte; leave the approved test original intact.
    const tamper=await fresh('native-');
    await mkdir(join(tamper,'task'),{mode:0o700});
    for(const name of ['evidence.json','review-manifest.json','task/main.swift'])
      await writeFile(join(tamper,name),await readFixed(join(yes.run,name),limits.source),{mode:0o600,flag:'wx'});
    const altered=await readFixed(join(yes.run,'task','app'),limits.binary);
    altered[altered.length-1]^=1;
    await writeFile(join(tamper,'task','app'),altered,{mode:0o700,flag:'wx'});
    try{await verifiedReceipt(join(tamper,'evidence.json'),true);throw new Error('modified-build-accepted');}
    catch(e){if(e.message!=='replay-binary-or-approval-mismatch')throw e;}
    const loose=await fresh('native-');
    await mkdir(join(loose,'task'),{mode:0o700});
    for(const name of ['evidence.json','review-manifest.json','task/main.swift'])
      await writeFile(join(loose,name),await readFixed(join(yes.run,name),limits.source),{mode:0o600,flag:'wx'});
    await symlink(join(yes.run,'task','app'),join(loose,'task','app'));
    try{await verifiedReceipt(join(loose,'evidence.json'),true);throw new Error('linked-build-accepted');}
    catch(e){if(e.message!=='unsafe-replay-input')throw e;}
    console.log('PASS replay-denies-wrong-unapproved-altered-and-linked-builds');
    await replayRun(join(yes.run,'evidence.json'),true);return;
  }
  if(['replay','native-app'].includes(cmd)){
    const allowTest=args[0]==='--allow-self-test';
    const [receipt,...rest]=allowTest?args.slice(1):args;
    if(cmd==='replay'&&rest.length)throw new Error('replay does not accept arbitrary arguments');
    await replayRun(receipt,allowTest,cmd==='native-app'?rest:null);return;
  }
  throw new Error('usage: native-live | verify-native | replay [--allow-self-test] <evidence.json> | native-app [--allow-self-test] <evidence.json> version|<occupied> <draft> <actions...>');
}
