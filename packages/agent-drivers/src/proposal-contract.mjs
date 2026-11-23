import { createHash } from 'node:crypto';
const hash = x => createHash('sha256').update(x).digest('hex');

export const requirement='Show only the tasks the user has already checked off.';
export const patchPrompt='Synthetic Atomium todo fixture (no tools). Audit is checked off, Ship is not. Current view shows unfinished tasks. The requested change is: '+requirement+' Choose one view among open, completed, all. Reply solely with a JSON object containing the single field view, no markdown or prose.';
export function parseProposal(text) {
  if(typeof text!=='string'||text.length>512||!/^\s*\{\s*"view"\s*:\s*"(open|completed|all)"\s*\}\s*$/.test(text))throw new Error('unsupported-proposal');
  return JSON.parse(text).view;
}
// The observed agy 1.5.14 message has ordinary ACP end_turn format. Store only a hash.
export const agyRegionStatusDigest='9896b44c9c9dc1a1b3ecc58e3cb689df55ff0c3b9182354197246634e07a5930';
export function providerStatus(source,digest){
  return source==='agy-acp-host'&&digest===agyRegionStatusDigest?'provider-region-unavailable':null;
}
export async function proposeView(receive,source='codex-host'){
  let text;
  try{text=await receive(patchPrompt);}
  catch{return {source,status:'provider-unavailable-or-unexpected'};}
  const status=typeof text==='string'?providerStatus(source,hash(text.trim())):null;
  if(status)return {source,status};
  let view;
  try{view=parseProposal(text);}
  catch{return {source,status:'proposal-schema-rejected'};}
  if(view!=='completed')return {source,status:'proposal-contract-rejected'};
  const patch={op:'replace',path:'view.json#/view',from:'open',value:view};
  return {source,status:'accepted',patch,patchSha256:hash(JSON.stringify(patch))};
}
