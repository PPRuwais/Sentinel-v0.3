import {scanFiles,redactSource} from './sentinel.mjs';
export const SCORE_VERSION='observed-priority-v1';
export const WEIGHTS={Critical:90,High:70,Medium:40,Low:15,Unknown:35};
export const normalizeName=name=>name.toLowerCase().replace(/[-_.]+/g,'-');
const object=v=>v&&typeof v==='object'&&!Array.isArray(v);
export function parsePythonGraph(report){
 if(!object(report)||report.version!=='1'||!Array.isArray(report.installed))throw new Error('Choose a pip inspect JSON report with format version 1. Run python -m pip inspect in your project environment.');
 if(report.installed.length>200)throw new Error('This prototype supports up to 200 installed distributions per application review. Export a project-specific virtual environment.');
 const nodes=[],edges=[],warnings=[];const names=new Set();
 for(const item of report.installed){
  const m=item.metadata;
  if(!object(m)||typeof m.name!=='string'||!/^[-A-Za-z0-9_.]{1,150}$/.test(m.name)||typeof m.version!=='string'||!m.version||m.version.length>100)throw new Error('A package has an invalid name or version.');
  const name=normalizeName(m.name);if(names.has(name))throw new Error('Duplicate normalized package name: '+name);names.add(name);
  if(m.requires_dist!==undefined&&(!Array.isArray(m.requires_dist)||m.requires_dist.length>100||m.requires_dist.some(x=>typeof x!=='string'||x.length>500)))throw new Error('Invalid requires_dist metadata for '+name);
  nodes.push({id:name,name,version:m.version,direct:item.requested===true,rootKnown:typeof item.requested==='boolean',requirements:(m.requires_dist||[]).slice(0,100)});
 }
 for(const n of nodes){
  for(const requirement of n.requirements){
   const match=requirement.match(/^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s*\[[^\]]*\])?(.*)$/);
   if(!match){warnings.push(`Could not parse a declared requirement for ${n.name}.`);continue;}
   const target=normalizeName(match[1]),marker=requirement.includes(';')?requirement.split(';').slice(1).join(';').trim():null;
   edges.push({from:n.id,to:target,requirement:requirement.slice(0,500),conditional:!!marker,marker,resolved:names.has(target),constraintVerified:false});
  }
  delete n.requirements;
 }
 if(nodes.some(n=>!n.rootKnown))warnings.push('Some requested/root flags are absent. Direct dependency classification is incomplete.');
 if(edges.some(e=>e.conditional))warnings.push('Environment markers and extras are preserved but not evaluated. Conditional edges are not proof of an active dependency.');
 if(edges.some(e=>!e.resolved))warnings.push('Some declared dependencies are absent from this environment; they may be optional or missing.');
 warnings.push('Dependency version constraints are not evaluated. A graph path is not runtime reachability or an exploit path.');
 return {format:'pip-inspect-v1',nodes,edges,warnings,environment:{pythonVersion:String(report.environment?.python_full_version||'unknown'),platform:String(report.environment?.sys_platform||'unknown')},createdAt:new Date().toISOString()};
}
export function dependencyPath(graph,target){
 const roots=graph.nodes.filter(n=>n.direct).map(n=>n.id),queue=roots.map(n=>({nodes:[n],conditional:false})),seen=new Set(roots);
 for(let i=0;i<queue.length;i++){
  const path=queue[i],last=path.nodes.at(-1);if(last===target)return path;
  for(const e of graph.edges.filter(e=>e.from===last&&e.resolved)){if(!seen.has(e.to)){seen.add(e.to);queue.push({nodes:[...path.nodes,e.to],conditional:path.conditional||e.conditional});}}
 }
 return null;
}
export function graphSBOM(graph,name){
 return {bomFormat:'CycloneDX',specVersion:'1.5',version:1,metadata:{timestamp:new Date().toISOString(),component:{type:'application',name}},components:graph.nodes.map(n=>({type:'library','bom-ref':n.id,name:n.name,version:n.version,purl:`pkg:pypi/${encodeURIComponent(n.name)}@${encodeURIComponent(n.version)}`})),dependencies:graph.nodes.map(n=>({ref:n.id,dependsOn:[...new Set(graph.edges.filter(e=>e.from===n.id&&e.resolved&&!e.conditional).map(e=>e.to))]})),properties:[{name:'sentinel:scope',value:'Declared unconditional edges to installed nodes only; conditional edges and constraints are not resolved. Full declarations are available in the application report.'}]};
}
export function checkApplicationFiles(files){
 const findings=[],coverage={sourceFiles:0,openapiFiles:0,dockerfiles:0,composeFiles:0,operations:0},warnings=[];
 const add=(f,ruleId,title,severity,location,why)=>findings.push({id:`${ruleId}:${f.path}:${location}`,ruleId,title,severity,path:f.path,location:String(location),why,kind:ruleId.startsWith('API')?'API':ruleId.startsWith('AUTH')?'Authentication':'Container',evidence:location});
 for(const f of files){
  let doc=null;
  if(/\.json$/i.test(f.path)){try{doc=JSON.parse(f.content);}catch{throw new Error('Invalid JSON: '+f.path);}}
  if(doc?.installed&&doc?.version==='1')continue;
  if(doc?.openapi){
   if(!/^3\./.test(doc.openapi)||!object(doc.paths))throw new Error('Only OpenAPI 3.x JSON with a paths object is supported.');
   coverage.openapiFiles++;
   if(doc.security!==undefined&&!Array.isArray(doc.security))throw new Error('Invalid OpenAPI security requirements.');
   for(const [path,item]of Object.entries(doc.paths)){
    if(!object(item)){warnings.push(`Unresolved or invalid path item: ${path}`);continue;}
    if(item.$ref)warnings.push(`Path reference is not resolved: ${path}`);
    for(const method of ['get','post','put','patch','delete','head','options','trace']){
     const op=item[method];if(!op)continue;
     if(!object(op)){warnings.push(`Invalid operation: ${method} ${path}`);continue;}
     coverage.operations++;const loc=`${method.toUpperCase()} ${path}`;
     if(op.$ref){warnings.push(`Operation reference is not resolved: ${loc}`);continue;}
     const auth=op.security===undefined?doc.security:op.security;
     if(auth!==undefined&&(!Array.isArray(auth)||auth.some(x=>!object(x))))throw new Error('Invalid security requirements on '+loc);
     if(!auth?.length||auth.some(r=>Object.keys(r).length===0))add(f,'API001','Operation permits anonymous access in the specification','Medium',loc,'No mandatory security requirement is declared. This may be intentional for public routes; verify the intended policy and actual server behavior.');
     else for(const requirement of auth)for(const scheme of Object.keys(requirement))if(!doc.components?.securitySchemes?.[scheme])add(f,'API002','Security scheme reference is missing','Medium',loc,`The declared security scheme ${scheme} is not defined locally. External references are not resolved.`);
    }
   }
   if(doc.servers!==undefined&&!Array.isArray(doc.servers))throw new Error('OpenAPI servers must be an array.');
   for(const srv of doc.servers||[])if(typeof srv.url==='string'&&srv.url.startsWith('http://'))add(f,'API003','Cleartext API server URL declared','Medium','servers','An HTTP URL appears in the API specification. It may describe development only; confirm that production uses HTTPS.');
   continue;
  }
  if(object(doc?.services)){
   coverage.composeFiles++;
   for(const [name,service]of Object.entries(doc.services)){
    if(!object(service)){warnings.push('Invalid Compose service: '+name);continue;}
    if(service.privileged===true)add(f,'CTR003','Privileged container configuration','High',name,'Privileged mode grants broad host capabilities. Verify whether this service needs them.');
    if(service.network_mode==='host')add(f,'CTR004','Host network configured','Medium',name,'Host networking removes the normal network namespace separation. Review exposure.');
    if(service.volumes!==undefined&&!Array.isArray(service.volumes))throw new Error('Compose service volumes must be an array. Export normalized Compose JSON.');
    for(const mount of service.volumes||[]){const source=typeof mount==='string'?mount.split(':')[0]:mount?.source;if(typeof source==='string'&&/docker\.sock$/.test(source))add(f,'CTR005','Docker socket mounted into container','Critical',name,'Access to the Docker daemon socket can provide control over the host. Review permissions and remove the mount if unnecessary.');}
   }
   continue;
  }
  if(/(?:^|\/)Dockerfile(?:\.[^/]*)?$/i.test(f.path)){
   coverage.dockerfiles++;let user=null,hasStage=false;
   f.content.split('\n').forEach((line,i)=>{const clean=line.trim();if(/^FROM\s/i.test(clean)){hasStage=true;user=null;if(/:latest(?:\s|$)/i.test(clean))add(f,'CTR001','Mutable latest image tag','Medium',i+1,'Pin and review a supported image digest for reproducible builds. This does not scan the image packages.');}if(/^USER\s/i.test(clean))user={value:clean.replace(/^USER\s+/i,'').trim(),line:i+1};});
   if(hasStage&&user&&/^(root|0)(?::[^\s]+)?(?:\s|$)/i.test(user.value))add(f,'CTR002','Final stage explicitly selects root','Medium',user.line,'The final stage explicitly selects root. Use a dedicated unprivileged user where practical.');
   else if(hasStage&&!user)add(f,'CTR006','Final stage has no explicit USER instruction','Low','final stage','The user is inherited from the base image and is unknown here. Inspect the built image before deciding whether this is a problem.');
   continue;
  }
  if(/\.(?:py|js|jsx|ts|tsx|mjs|cjs)$/i.test(f.path)){
   coverage.sourceFiles++;
   findings.push(...scanFiles([f]).findings.map(x=>({id:x.id,ruleId:x.ruleId,title:x.title,severity:x.severity,path:x.path,location:String(x.line),why:x.why,kind:'Source',evidence:x.excerpt})));
   f.content.split('\n').forEach((line,i)=>{
    if(/^\s*(?:#|\/\/)/.test(line))return;
    if(/(?:["']?verify_signature["']?\s*:\s*(?:false|False)|\bverify\s*=\s*False.*jwt|jwt\s*\.\s*decode\([^\n]*verify\s*=\s*False)/.test(line))add(f,'AUTH001','JWT signature verification appears disabled','High',i+1,'A supported source pattern disables token signature verification. Inspect the complete authentication flow; static matching is not an authorization test.');
    if(/(?:["']?verify_exp["']?\s*:\s*(?:false|False)|ignoreExpiration\s*:\s*true)/.test(line))add(f,'AUTH002','Token expiry verification appears disabled','Medium',i+1,'Expiry validation appears disabled. Review whether expired credentials could be accepted.');
   });
   continue;
  }
  warnings.push('No application-review parser for '+f.path+'. Use source files, Dockerfile, pip inspect JSON, OpenAPI JSON, or normalized Compose JSON.');
 }
 return {findings,coverage,warnings,scannedAt:new Date().toISOString()};
}
export function applicationAssessment(app){
 const items=[...(app.checks?.findings||[])];
 for(const p of app.advisories?.packages||[])for(const a of p.advisories||[])items.push({id:`DEP:${p.name}:${a.id}`,kind:'Dependency',severity:a.severity||'Unknown',title:a.summary||a.id,path:`${p.name}@${p.version}`,why:`OSV matched ${a.id} to this package version. This is not proof that the vulnerable behavior is reachable.`,advisory:a.id});
 const graphResolved=!!app.graph?.nodes.length&&app.graph.nodes.every(n=>n.rootKnown)&&app.graph.edges.every(e=>e.resolved&&!e.conditional);
 const complete=graphResolved&&app.advisories?.status==='complete'&&(app.checks?.warnings?.length||0)===0;
 const score=items.length?Math.max(...items.map(i=>WEIGHTS[i.severity]??WEIGHTS.Unknown)):null;
 const blockers=items.filter(i=>['Critical','High'].includes(i.severity));
 return {score,scoreVersion:SCORE_VERSION,formula:'Maximum observed finding weight: Critical 90, High 70, Medium 40, Low 15, Unknown severity 35. No findings yields no numeric score. This is a triage index, not CVSS, EPSS, or compromise probability.',decision:blockers.length?'BLOCK':!complete||items.some(i=>i.severity==='Unknown')?'REVIEW_REQUIRED':'NO_HIGH_BLOCKERS_IN_SUPPLIED_SCOPE',blockers:blockers.length,findings:items,coverage:{dependencyGraph:!!app.graph,declaredGraphResolved:graphResolved,vulnerabilityLookup:app.advisories?.status||'not_run',...app.checks?.coverage,runtimeReachability:'not_tested',apiEnforcement:'not_tested',containerImageVulnerabilities:'not_scanned'},limitations:[...(app.graph?.warnings||[]),...(app.checks?.warnings||[]),'No live endpoint testing or built-image scanning. No score predicts future vulnerabilities.']};
}
export function applicationEvidence(app){
 const assessment=applicationAssessment(app),records=[];
 records.push({id:'scope',source:'Assessment coverage',detail:JSON.stringify(assessment.coverage)});
 records.push({id:'priority',source:SCORE_VERSION,detail:JSON.stringify({score:assessment.score,decision:assessment.decision,formula:assessment.formula})});
 if(app.graph)records.push({id:'graph',source:'Python installed metadata',detail:`${app.graph.nodes.length} installed distributions; ${app.graph.edges.length} declared edges. Environment markers/extras and constraints are not evaluated. Graph paths do not establish exploitability.`});
 const sorted=[...assessment.findings].sort((a,b)=>(WEIGHTS[b.severity]||35)-(WEIGHTS[a.severity]||35));
 for(const [i,f]of sorted.slice(0,22).entries()){
  const node=f.kind==='Dependency'?app.graph?.nodes.find(n=>`${n.name}@${n.version}`===f.path):null;
  const path=node?dependencyPath(app.graph,node.id):null;
  records.push({id:'finding-'+(i+1),source:redactSource(f.path).content.slice(0,250),detail:redactSource(JSON.stringify({kind:f.kind,severity:f.severity,title:f.title,location:f.location,why:f.why,advisory:f.advisory,declaredDependencyPath:path})).content.slice(0,1400)});
 }
 records.push({id:'limitations',source:'Evidence boundary',detail:assessment.limitations.join(' ').slice(0,1800)});
 return {records,totalFindings:assessment.findings.length,includedFindings:Math.min(22,sorted.length)};
}
