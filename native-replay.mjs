import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,mkdtemp,readFile,writeFile,realpath,lstat} from 'node:fs/promises';
import {join,dirname,basename,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline/promises';

const execute=promisify(execFile);
const sha=x=>createHash('sha256').update(x).digest('hex');
const stable=x=>JSON.stringify(x);
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
  const compilerSha=sha(await readFile(compiler));
  return {developer,compiler,version,sdk,bin,commands,compilerSha};
}
function restricted(task,binary,tools) {
  const system=['/System/Library','/usr/lib'];
  const readonly=tools?[...system,tools.developer,join(dirname(tools.developer),'SharedFrameworks')]:system;
  const commands=tools?tools.commands:[binary];
  return [
    '(version 1)(deny default)(allow process-fork)(allow signal (target self))(allow ipc-posix-sem*)(allow sysctl-read)(allow file-read-metadata)',
    '(allow file-read-data '+[sub(task),...readonly.map(sub),...['/','/dev/null','/dev/urandom'].map(literal)].join(' ')+')',
    '(allow file-map-executable '+[sub(task),...readonly.map(sub)].join(' ')+')',
    '(allow process-exec '+commands.map(literal).join(' ')+')',
    '(allow file-write* '+sub(task)+' '+literal('/dev/null')+')',
  ].join('\n');
}
async function inSandbox(task,profile,command,args,timeout=8000,toolPath='') {
  const env={HOME:task,TMPDIR:task,PATH:toolPath?toolPath+':/usr/bin:/bin':'/usr/bin:/bin',LANG:'C'};
  try {
    const result=await execute('/usr/bin/sandbox-exec',['-p',profile,command,...args],{cwd:task,env,timeout,maxBuffer:65536});
    return {ok:true,stdout:result.stdout.trimEnd()};
  } catch(e) {
    const why=String(e.stderr??'');
    return {ok:false,error:why.includes('sandbox_apply')?'nested-sandbox-denied':why.includes('Operation not permitted')?'sandbox-operation-denied':'sandboxed-command-failed',exitCode:Number.isInteger(e.code)?e.code:null,signal:e.signal??null};
  }
}
async function appSuite(task,binary) {
  const profile=restricted(task,binary);
  const checks=[];
  for(const [id,args,expected] of t){
    const observation=await inSandbox(task,profile,binary,args);
    const actual=observation.ok?observation.stdout.split('\n'):null;
    const pass=observation.ok&&stable(actual)===stable(expected);
    checks.push({id,pass,expected,actual,...(!observation.ok?{error:observation.error}:{})});
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
    await outputAt(run,{version:1,mode,status,specSha,suiteSha,proposal,review,approval:null,exported:false,...more});
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
  await writeFile(source,c.proposed,{mode:0o600,flag:'wx'});
  if(sha(await readFile(source))!==c.sourceSha)return fail('source-binding-mismatch');
  const tools=await toolchain();
  const cache=join(task,'cache');
  await mkdir(cache,{mode:0o700});
  const profile=restricted(task,binary,tools);
  const result=await inSandbox(task,profile,tools.compiler,['-sdk',tools.sdk,'-module-cache-path',cache,source,'-o',binary],35000,tools.bin);
  if(!result.ok)return fail('swift-compile-failed',{build:result});
  if(sha(await readFile(source))!==c.sourceSha)return fail('post-build-source-binding-mismatch');
  const buildSha=sha(await readFile(binary));
  const build={sourceSha:c.sourceSha,buildSha,profileSha:sha(profile),toolchain:tools.version,compilerSha:tools.compilerSha};
  const {runtimeProfileSha,checks}=await appSuite(task,binary);
  const green=checks.every(c=>c.pass);
  if(!green)return fail('behavior-rejected',{build,checks,runtimeProfileSha,manifestSha:c.manifestSha,sourceSha:c.sourceSha});
  if(sha(await readFile(binary))!==buildSha||sha(await readFile(source))!==c.sourceSha)return fail('post-test-build-binding-mismatch');
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
  await outputAt(run,{version:1,mode,status,specSha,suiteSha,proposal,review,manifestSha:c.manifestSha,sourceSha:c.sourceSha,build,checks,runtimeProfileSha,approval,exported:false});
  console.log(status+' build '+buildSha);
  return {run,status};
}

async function verifiedReceipt(raw,allowTest) {
  if(!raw)throw new Error('receipt-path-required');
  const path=resolve(raw);
  const run=dirname(path);
  if(basename(path)!=='evidence.json'||dirname(run)!==runs||!/^native-[a-zA-Z0-9]+$/.test(basename(run))||await realpath(path)!==path)throw new Error('receipt-is-not-an-Atomium-native-run');
  const st=await lstat(path);
  if(!st.isFile()||st.size>30000)throw new Error('receipt-invalid');
  const r=JSON.parse(await readFile(path,'utf8'));
  const kind=r.approval?.kind;
  if(kind!=='interactive'&&!(allowTest&&kind==='self-test-only'))throw new Error('exact-candidate-not-approved');
  if(r.version!==1||r.status!=='replay-authorized'||r.specSha!==specSha||r.suiteSha!==suiteSha||r.proposal?.rule!=='exact-raw-name'||r.checks?.length!==t.length||r.checks.some((check,i)=>!check.pass||check.id!==t[i][0]))throw new Error('receipt-contract-mismatch');
  const c=candidateManifest('exact-raw-name');
  const boundApproval=(kind==='interactive'&&r.mode==='native-live'&&r.proposal.source==='agy-acp-host'&&r.proposal.status==='accepted'&&r.review?.verdict==='accept'&&r.review.status==='accepted'&&r.review.manifestSha===c.manifestSha)
    || (kind==='self-test-only'&&r.mode==='native-self-test'&&r.proposal.source==='trusted-self-test');
  if(!boundApproval)throw new Error('approval-mode-binding-mismatch');
  const manifestPath=join(run,'review-manifest.json'),src=join(run,'task','main.swift'),bin=join(run,'task','app');
  for(const item of [manifestPath,src,bin])if(!(await lstat(item)).isFile()||await realpath(item)!==item)throw new Error('unsafe-replay-input');
  if(sha(await readFile(manifestPath))!==c.manifestSha||sha(await readFile(src))!==c.sourceSha)throw new Error('frozen-candidate-tampered');
  const bytes=await readFile(bin);
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
  await writeFile(binary,reviewed.bytes,{mode:0o700,flag:'wx'});
  if(sha(await readFile(binary))!==reviewed.binding.buildSha)throw new Error('replay-copy-binding-mismatch');
  if(appArgs){
    const okay=appArgs.length===1&&appArgs[0]==='version'||appArgs.length>=3&&appArgs.length<=24&&appArgs.every(x=>x.length<=64&&!/[\x00-\x1f\x7f]/.test(x))&&appArgs.slice(2).every(x=>['show','save','submit','reset'].includes(x)||/^rename:.{1,50}$/.test(x));
    if(!okay)throw new Error('fixture-input-invalid; use version or occupiedName draftName actions: show save submit rename:NAME reset');
    const result=await inSandbox(task,restricted(task,binary),binary,appArgs);
    if(!result.ok)throw new Error(result.error);
    console.log(result.stdout);
    return;
  }
  const {runtimeProfileSha,checks}=await appSuite(task,binary);
  const passed=checks.every(x=>x.pass)&&sha(await readFile(binary))===reviewed.binding.buildSha;
  await outputAt(run,{version:1,mode:'replay',sourceApproval:reviewed.kind,binding:reviewed.binding,runtimeProfileSha,checks,passed,usedModel:false});
  if(!passed)process.exitCode=1;
}
export async function nativeMain(cmd,args,{askCodex,proposeAgy}) {
  if(cmd==='native-live'&&args.length===0){const r=await buildPair(cmd,askCodex,proposeAgy);if(!['verified-not-approved','replay-authorized'].includes(r.status))process.exitCode=1;return;}
  if(cmd==='verify-native'&&args.length===0){
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
      await writeFile(join(tamper,name),await readFile(join(yes.run,name)),{mode:0o600,flag:'wx'});
    const altered=await readFile(join(yes.run,'task','app'));
    altered[altered.length-1]^=1;
    await writeFile(join(tamper,'task','app'),altered,{mode:0o700,flag:'wx'});
    try{await verifiedReceipt(join(tamper,'evidence.json'),true);throw new Error('modified-build-accepted');}
    catch(e){if(e.message!=='replay-binary-or-approval-mismatch')throw e;}
    console.log('PASS replay-denies-wrong-unapproved-and-altered-builds');
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
