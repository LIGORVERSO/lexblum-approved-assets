#!/usr/bin/env node
/** GitHub-owned TESTES release publisher. No Cloudflare token, no private signing key.
 * A request committed under requests/testes/ triggers the opt-in workflow.
 * Release first; update channels/testes.json only after uploaded bytes are confirmed.
 */
import {readFile, lstat, writeFile, mkdir} from 'node:fs/promises';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {join,basename,resolve,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';

const REPO='LIGORVERSO/lexblum-approved-assets';
const sha=x=>createHash('sha256').update(x).digest('hex');
const hex=/^[0-9a-f]{64}$/;
const safeName=/^(?:[0-9a-f]{64}|(?:oga-|sdc-)?catalog\.envelope)$/;
const safeTag=/^[a-z0-9][a-z0-9._-]{0,80}$/;
const bail=(m)=>{throw new Error('LEXBLUM_TEST_PUBLICATION_BLOCKED:'+m)};
const args=process.argv.slice(2),requestPath=args[0],checkOnly=args[1]==='--check';
if(!requestPath || !/^requests\/testes\/[a-z0-9._-]+\.json$/.test(requestPath) ||
   (args[1] && !checkOnly))bail('REQUEST_PATH');
function canonical(value){
 if(value===null)return 'null';
 if(['string','boolean'].includes(typeof value))return JSON.stringify(value);
 if(typeof value==='number')return Number.isSafeInteger(value)?String(value):bail('NONINTEGER_VALUE');
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 bail('INVALID_JSON_VALUE');
}
function gh(args){
 const r=spawnSync('gh',args,{encoding:'utf8',timeout:240000,maxBuffer:4*1024*1024,env:process.env});
 if(r.error||r.status!==0)bail('GITHUB_COMMAND_FAILED:'+args.slice(0,3).join(' ') + ':'+String(r.stderr||r.error).slice(0,250));
 return r.stdout.trim();
}
function getExistingRelease(tag){
 const r=spawnSync('gh',['api',`repos/${REPO}/releases/tags/${tag}`],{encoding:'utf8',timeout:30000});
 if(r.status===0)return JSON.parse(r.stdout);
 if(r.status===1&&/404|Not Found/i.test(r.stderr||''))return null;
 bail('RELEASE_LOOKUP_UNCERTAIN');
}
async function main(){
 if(!checkOnly&&process.env.GITHUB_REPOSITORY!==REPO)bail('WRONG_REPOSITORY');
 const req=JSON.parse(await readFile(requestPath,'utf8'));
 if(req.schema!=='lexblum.test-release-request.v1'||req.channel!=='TESTES'||
    req.classification!=='ENGINEERING_TEST_ONLY'||
    req.repository!==REPO||typeof req.tag!=='string'||!safeTag.test(req.tag)||
    !req.tag.includes('testes')||basename(requestPath)!==req.tag+'.json'||
    typeof req.publicKeyBase64!=='string'||
    !/^[A-Za-z0-9+/]{43}=$/.test(req.publicKeyBase64)||
    !Array.isArray(req.assets)||req.assets.length<2||req.assets.length>2000||
    req.rightsReviewed!==true||req.secretScanReviewed!==true)
  bail('REQUEST_CONTRACT');
 const raw=Buffer.from(req.publicKeyBase64,'base64');
 if(raw.length!==32||raw.toString('base64')!==req.publicKeyBase64)bail('PUBLIC_KEY_FORMAT');
 const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),raw]),format:'der',type:'spki'});
 const names=new Set(),files=[];
 for(const item of req.assets){
  if(!item||typeof item.name!=='string'||!safeName.test(item.name)||names.has(item.name)||
     !hex.test(item.sha256)||!Number.isSafeInteger(item.size)||item.size<=0||item.size>90*1024*1024)
   bail('ASSET_MANIFEST_INVALID');
  names.add(item.name);
  const file=resolve('staging','testes',req.tag,item.name);
  const stat=await lstat(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size!==item.size)bail('ASSET_SIZE_OR_TYPE:'+item.name);
  const bytes=await readFile(file);
  if(sha(bytes)!==item.sha256 || (hex.test(item.name)&&item.name!==item.sha256))bail('ASSET_HASH:'+item.name);
  files.push(file);
  if(item.name.endsWith('catalog.envelope')){
   let data;
   try{data=JSON.parse(bytes.toString('utf8'));}catch{bail('ENVELOPE_JSON');}
   if(data.schema!=='lexblum.resource.envelope.v1'||data.payload?.channel!=='TESTES'||
      data.payload?.schema!=='lexblum.resource.catalog.v1'||
      !Array.isArray(data.payload.objects))bail('ENVELOPE_CONTRACT');
   const signature=Buffer.from(data.signatureBase64||'','base64');
   if(signature.length!==64||!verify(null,Buffer.from(canonical(data.payload)),key,signature))bail('ENVELOPE_SIGNATURE');
   const worldId=item.name==='oga-catalog.envelope'?'oga.pl':
     item.name==='sdc-catalog.envelope'?'lexblum':null;
   if(worldId){
    if(data.payload.world?.id!==worldId||!Array.isArray(data.payload.world.files)||
       !data.payload.objects.some(o=>o.kind==='WORLD_REGION'))bail('WORLD_IDENTITY_OR_REGION');
   } else if(data.payload.world!==null)bail('RESOURCES_CATALOG_WORLD_NOT_NULL');
   if(!data.payload.objects.length)bail('CATALOG_EMPTY');
   for(const object of data.payload.objects){
    if(!hex.test(object.sha256)||!Number.isSafeInteger(object.bytes)||object.bytes<=0)bail('CATALOG_OBJECT');
    const referenced=req.assets.find(x=>x.name===object.sha256);
    if(!referenced||referenced.size!==object.bytes)bail('CATALOG_OBJECT_MISSING:'+object.sha256);
   }
  }
 }
 const changedChannels=Object.entries({resources:'catalog.envelope',oga:'oga-catalog.envelope',sdc:'sdc-catalog.envelope'})
   .filter(([,filename])=>names.has(filename)).map(([channel])=>channel);
 if(!changedChannels.length)bail('NO_SIGNED_CATALOG');
 const expected=new Set(req.assets.filter(a=>hex.test(a.name)).map(a=>a.name));
 if(expected.size<1)bail('NO_OBJECTS');
 console.log(JSON.stringify({status:'VALIDATED_LOCAL_TEST_ASSETS',tag:req.tag,assets:files.length,checkOnly}));
 if(checkOnly)return;
 if(getExistingRelease(req.tag))bail('RELEASE_TAG_ALREADY_EXISTS');
 gh(['release','create',req.tag,...files,'-R',REPO,'--draft','--prerelease','--latest=false',
     '--target','main','--title',`TESTES ${req.tag}`,'--notes','Technical test-only world packs. No canonical/production approval.']);
 const uploaded=getExistingRelease(req.tag);
 if(!uploaded||!uploaded.draft||!Array.isArray(uploaded.assets)||uploaded.assets.length!==req.assets.length)bail('DRAFT_READBACK');
 for(const item of req.assets){
  const a=uploaded.assets.find(x=>x.name===item.name);
  if(!a||a.size!==item.size||a.state!=='uploaded'||a.digest!=='sha256:'+item.sha256)bail('REMOTE_ASSET_READBACK:'+item.name);
 }
 gh(['release','edit',req.tag,'-R',REPO,'--draft=false','--prerelease','--latest=false']);
 const published=getExistingRelease(req.tag);
 if(!published||published.draft||!published.prerelease)bail('PRERELEASE_READBACK');
 const apiPath=`repos/${REPO}/contents/channels/testes.json`;
 let oldSha=null,oldTags={};
 const check=spawnSync('gh',['api',apiPath],{encoding:'utf8',timeout:30000});
 if(check.status===0){
  const old=JSON.parse(check.stdout);oldSha=old.sha;
  const prev=JSON.parse(Buffer.from(old.content.replace(/\s/g,''),'base64').toString('utf8'));
  if(prev.schema!=='lexblum.test-channel-pointer.v1'||prev.channel!=='TESTES'||
     prev.state!=='PUBLISHED'||prev.repository!==REPO)bail('EXISTING_POINTER_INVALID');
  if(prev.tags&&typeof prev.tags==='object'&&!Array.isArray(prev.tags))oldTags=prev.tags;
  else if(typeof prev.tag==='string')oldTags={resources:prev.tag,oga:prev.tag,sdc:prev.tag};
  else bail('EXISTING_POINTER_FORMAT');
 } else if(!/404|Not Found/i.test(check.stderr||''))bail('POINTER_LOOKUP_UNCERTAIN');
 const tags={...oldTags};
 for(const channel of changedChannels)tags[channel]=req.tag;
 const pointer={schema:'lexblum.test-channel-pointer.v1',channel:'TESTES',state:'PUBLISHED',repository:REPO,tags};
 // A joint MT release remains consumable by the already deployed single-tag Worker.
 // A later split never leaves a stale shared tag behind.
 if(tags.oga&&tags.sdc&&tags.oga===tags.sdc&&
    (!tags.resources||tags.resources===tags.oga))pointer.tag=tags.oga;
 const rawPointer=Buffer.from(JSON.stringify(pointer)+'\n').toString('base64');
 const change=['api','-X','PUT',apiPath,'-f',`message=publish(TESTES): ${req.tag}`,
  '-f',`content=${rawPointer}`,'-f','branch=main'];
 if(oldSha)change.push('-f',`sha=${oldSha}`);
 gh(change);
 const verifyPointer=JSON.parse(gh(['api',apiPath]));
 if(!verifyPointer.content||Buffer.from(verifyPointer.content.replace(/\s/g,''),'base64').toString('utf8')!==JSON.stringify(pointer)+'\n')bail('POINTER_READBACK');
 console.log(JSON.stringify({status:'TEST_CHANNEL_PUBLISHED',tag:req.tag,release:published.html_url,pointer:'channels/testes.json'}));
}
main().catch(e=>{console.error(String(e.message));process.exitCode=2;});
