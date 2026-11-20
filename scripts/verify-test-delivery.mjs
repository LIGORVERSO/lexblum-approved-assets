#!/usr/bin/env node
/** Read-only HTTPS transport check for signed TESTES catalogues and immutable objects.
 * Not an APK builder, installer, release publisher or material approval.
 */
import {readFile} from 'node:fs/promises';
import {createHash,createPublicKey,verify} from 'node:crypto';
const die=(msg)=>{throw new Error('MT_HTTPS_E2E_FAILED:'+msg)};
const requestFile=process.argv[2];
if(!requestFile||!/^requests\/testes\/[a-z0-9._-]+\.json$/.test(requestFile))die('INVALID_REQUEST_PATH');
const req=JSON.parse(await readFile(requestFile,'utf8'));
if(req.schema!=='lexblum.test-release-request.v1'||req.channel!=='TESTES'||req.assets?.length<2)die('REQUEST_INVALID');
const root='https://lexblum-content.ligorverso.workers.dev/testes/';
const raw=Buffer.from(req.publicKeyBase64,'base64');
if(raw.length!==32||raw.toString('base64')!==req.publicKeyBase64)die('PUBLIC_KEY_INVALID');
const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),raw]),format:'der',type:'spki'});
function canonical(v){
 if(v===null)return 'null';
 if(typeof v==='string'||typeof v==='boolean')return JSON.stringify(v);
 if(typeof v==='number')return Number.isSafeInteger(v)?String(v):die('INVALID_NUMBER');
 if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
 if(typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
 die('UNSUPPORTED_VALUE');
}
const hash=buf=>createHash('sha256').update(buf).digest('hex');
async function fetchChecked(path,{method='GET',headers={}}={}){
 const u=new URL(path,root);
 if(u.origin!==new URL(root).origin||!u.pathname.startsWith('/testes/'))die('ORIGIN_CHANGED');
 let response;
 try{response=await fetch(u,{method,headers,redirect:'manual',signal:AbortSignal.timeout(45000)});}
 catch(err){die('NETWORK_'+method+'_'+path+'_'+String(err.cause?.code||err.message).slice(0,100));}
 return response;
}
async function readLimited(res,limit,path){
 if(!res.body)die('EMPTY_BODY_'+path);
 const chunks=[];let bytes=0;
 for await(const part of res.body){bytes+=part.byteLength;if(bytes>limit)die('OVERSIZED_'+path);chunks.push(part);}
 return Buffer.concat(chunks,bytes);
}
const expected=new Map(req.assets.map(x=>[x.name,x]));
const evidence=[];
for(const [path,id,name] of [
 ['catalog.envelope',null,'catalog.envelope'],
 ['oga/catalog.envelope','oga.pl','oga-catalog.envelope'],
 ['sdc/catalog.envelope','lexblum','sdc-catalog.envelope']
]){
 const meta=expected.get(name);
 if(!meta)continue;
 const cat=await fetchChecked(path);
 if(cat.status!==200)die('CATALOG_HTTP_'+path+'_'+cat.status);
 const bytes=await readLimited(cat,6*1024*1024,path);
 if(bytes.length!==meta.size||hash(bytes)!==meta.sha256)die('CATALOG_BYTES_'+path);
 let envelope;
 try{envelope=JSON.parse(bytes.toString('utf8'))}catch{die('CATALOG_JSON_'+path)}
 const signature=Buffer.from(envelope.signatureBase64||'','base64');
 if(envelope.schema!=='lexblum.resource.envelope.v1'||signature.length!==64||
   !verify(null,Buffer.from(canonical(envelope.payload)),key,signature)||
   envelope.payload.channel!=='TESTES'||envelope.payload.world?.id!==id)die('CATALOG_SIGNATURE_OR_ID_'+path);
 const head=await fetchChecked(path,{method:'HEAD'});
 if(head.status!==200)die('HEAD_CATALOG_'+path+'_'+head.status);
 evidence.push({world:id,manifest:name,bytes:bytes.length,objects:envelope.payload.objects.length});
}
const objs=req.assets.filter(a=>/^[0-9a-f]{64}$/.test(a.name));
const suppliedCatalogs=[...expected.keys()].filter(name=>name.endsWith('catalog.envelope'));
if(!evidence.length||evidence.length!==suppliedCatalogs.length||objs.length<1)
 die('INDEPENDENT_CHANNEL_MANIFEST_MISMATCH');
for(const item of objs){
 const response=await fetchChecked(item.name);
 if(response.status!==200)die('OBJECT_HTTP_'+item.name+'_'+response.status);
 const bytes=await readLimited(response,item.size+1,item.name);
 if(bytes.length!==item.size||hash(bytes)!==item.sha256)die('OBJECT_SHA_'+item.name);
}
const first=objs[0];
const partial=await fetchChecked(first.name,{headers:{Range:'bytes=0-'}});
if(partial.status!==206)die('RANGE_HTTP_'+partial.status);
const body=await readLimited(partial,first.size+1,'range');
if(body.length!==first.size||hash(body)!==first.sha256)die('RANGE_HASH');
const expectedRange=`bytes 0-${first.size-1}/${first.size}`;
if(partial.headers.get('content-range')!==expectedRange)die('RANGE_HEADER');
const etag=partial.headers.get('etag');
if(etag&&/^"[^"\r\n]+"$/.test(etag)){
 const follow=await fetchChecked(first.name,{headers:{Range:'bytes=0-','If-Range':etag}});
 if(follow.status!==206)die('IF_RANGE_HTTP_'+follow.status);
 const resumed=await readLimited(follow,first.size+1,'if-range');
 if(hash(resumed)!==first.sha256)die('IF_RANGE_HASH');
}
console.log(JSON.stringify({status:'MT_HTTPS_SIGNED_DISTRIBUTION_PASS',origin:root,worlds:evidence,verifiedObjects:objs.length,head:true,range:true,ifRangeChecked:!!etag,androidInstallVerified:false}));
