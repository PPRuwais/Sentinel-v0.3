import {AIError} from './ai.mjs';
import {normalizeName} from '../dist/application-core.mjs';
const base='https://api.osv.dev/v1';
export function normalizeAdvisory(data,pkg){
 const affected=(data.affected||[]).filter(a=>a.package?.ecosystem==='PyPI'&&normalizeName(a.package.name||'')===pkg.name);
 const labels=[data.database_specific?.severity,...affected.flatMap(a=>[a.database_specific?.severity,a.ecosystem_specific?.severity])].map(x=>typeof x==='string'?x.toUpperCase():'');
 const severity=['CRITICAL','HIGH','MODERATE','MEDIUM','LOW'].find(s=>labels.includes(s));
 return {id:data.id,aliases:(data.aliases||[]).filter(x=>typeof x==='string'),summary:String(data.summary||data.id).slice(0,600),severity:severity?severity==='MODERATE'?'Medium':severity[0]+severity.slice(1).toLowerCase():'Unknown',severitySource:severity?'OSV database/ecosystem severity label':'No supported severity label; CVSS vectors are retained, not converted',cvss:[...(data.severity||[]),...affected.flatMap(a=>a.severity||[])].filter(s=>typeof s.score==='string').map(s=>({type:s.type,vector:s.score})),fixedVersions:[...new Set(affected.flatMap(a=>(a.ranges||[]).flatMap(r=>(r.events||[]).filter(e=>typeof e.fixed==='string').map(e=>e.fixed))))],modified:data.modified||null,url:'https://osv.dev/vulnerability/'+encodeURIComponent(data.id),detailStatus:'complete',note:'Listed fixed versions may belong to different release branches. Verify affected ranges, dependency constraints, and compatibility before upgrading.'};
}
export function createOSVService({fetchImpl=globalThis.fetch}={}){
 async function request(path,body){
  try{
   const res=await fetchImpl(base+path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json'}:undefined,body:body?JSON.stringify(body):undefined,redirect:'error',signal:AbortSignal.timeout(15000)});
   if(!res.ok)throw new Error('HTTP '+res.status);
   const text=await res.text();if(text.length>8000000)throw new Error('Response too large');return JSON.parse(text);
  }catch{throw new AIError('OSV lookup failed or timed out. No clean result can be inferred; check your internet connection and retry.',502,'osv_unavailable');}
 }
 async function lookup(input){
  if(input?.consent!==true)throw new AIError('Explicit consent is required to send package names and versions to OSV.',400,'consent_required');
  if(!Array.isArray(input.packages)||input.packages.length<1||input.packages.length>200)throw new AIError('Provide 1 to 200 packages.');
  const packages=input.packages.map(p=>{if(typeof p?.name!=='string'||!/^[-A-Za-z0-9_.]{1,150}$/.test(p.name)||typeof p.version!=='string'||!p.version||p.version.length>100||/[\s\x00-\x1f]/.test(p.version))throw new AIError('Invalid package identity.');return {name:normalizeName(p.name),version:p.version};});
  if(new Set(packages.map(p=>p.name)).size!==packages.length)throw new AIError('Duplicate package name.');
  const queries=packages.map(p=>({package:{name:p.name,ecosystem:'PyPI'},version:p.version}));
  const records=packages.map(p=>({...p,matches:[],next:null}));
  let pending=records.map((_,i)=>i),partial=false;
  for(let page=0;page<3&&pending.length;page++){
   const data=await request('/querybatch',{queries:pending.map(i=>({...queries[i],...(records[i].next?{page_token:records[i].next}:{})}))});
   if(!Array.isArray(data.results)||data.results.length!==pending.length)throw new AIError('OSV returned an incomplete batch response.',502,'invalid_osv_response');
   const next=[];
   pending.forEach((index,i)=>{const r=data.results[i];if(!r||r.error||(r.vulns!==undefined&&!Array.isArray(r.vulns)))throw new AIError('OSV returned an invalid package result.',502,'invalid_osv_response');for(const v of r.vulns||[]){if(typeof v.id!=='string'||!/^[-A-Za-z0-9_.:]{1,200}$/.test(v.id))throw new AIError('OSV returned an invalid advisory ID.',502,'invalid_osv_response');records[index].matches.push(v.id);}records[index].next=r.next_page_token||null;if(records[index].next)next.push(index);});pending=next;
  }
  if(pending.length)partial=true;
  const ids=[...new Set(records.flatMap(r=>r.matches))],details=new Map();let cursor=0;
  await Promise.all(Array.from({length:Math.min(6,ids.length)},async()=>{while(cursor<Math.min(ids.length,80)){const id=ids[cursor++];try{const d=await request('/vulns/'+encodeURIComponent(id));if(d.id!==id)throw new Error('ID mismatch');details.set(id,d);}catch{partial=true;}}}));
  if(ids.length>80)partial=true;
  return {status:partial?'partial':'complete',provider:'OSV',checkedAt:new Date().toISOString(),metadataSent:'Package name, ecosystem PyPI, exact version. Source code is not sent.',packages:records.map(r=>({...packages.find(p=>p.name===r.name),paginationComplete:!r.next,advisories:[...new Set(r.matches)].filter(id=>!details.get(id)?.withdrawn).map(id=>details.has(id)?normalizeAdvisory(details.get(id),r):{id,summary:'Advisory matched; details unavailable',severity:'Unknown',fixedVersions:[],aliases:[],cvss:[],url:'https://osv.dev/vulnerability/'+encodeURIComponent(id),detailStatus:'unavailable'})})),warnings:partial?['Lookup is partial: pagination, detail limits, or network failures prevented a complete result. Unknown is not safe.']:[],scope:'Known version-matched advisories at this timestamp; no call-graph reachability, EPSS forecasting, or guarantee of absence of vulnerabilities.'};
 }
 return {lookup};
}
