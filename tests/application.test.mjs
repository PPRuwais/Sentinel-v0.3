import test from 'node:test';
import assert from 'node:assert/strict';
import {parsePythonGraph,dependencyPath,checkApplicationFiles,applicationAssessment,applicationEvidence,graphSBOM} from '../dist/application-core.mjs';
import {createOSVService,normalizeAdvisory} from '../lib/osv.mjs';
import {prepareApplicationReview,validateApplicationReview} from '../lib/application-ai.mjs';
import {createAIService} from '../lib/ai.mjs';
const inventory=()=>({version:'1',environment:{python_full_version:'3.12.0',sys_platform:'linux'},installed:[{requested:true,metadata:{name:'App_Client',version:'1.0',requires_dist:['http-lib>=1','optional-lib; python_version < "3.9"']}},{requested:false,metadata:{name:'http-lib',version:'1.2',requires_dist:['shared==2']}},{requested:false,metadata:{name:'shared',version:'2',requires_dist:['http-lib>=1']}}]});
const emptyChecks=()=>checkApplicationFiles([]);
test('Python graph normalizes names and retains transitive paths, missing edges, and unevaluated conditions',()=>{
 const graph=parsePythonGraph(inventory());assert.equal(graph.nodes[0].name,'app-client');assert.deepEqual(dependencyPath(graph,'shared').nodes,['app-client','http-lib','shared']);assert.equal(graph.edges.find(e=>e.to==='optional-lib').resolved,false);assert.equal(graph.edges.find(e=>e.to==='optional-lib').conditional,true);assert.ok(graph.warnings.length>=2);
 assert.equal(graph.nodes[1].direct,false);assert.equal(dependencyPath(graph,'missing'),null);
});
test('Python graph rejects wrong schema, duplicate names and excessive environments',()=>{
 assert.throws(()=>parsePythonGraph({version:'2',installed:[]}));
 const dup=inventory();dup.installed.push({metadata:{name:'app-client',version:'2'}});assert.throws(()=>parsePythonGraph(dup),/Duplicate/);
 assert.throws(()=>parsePythonGraph({version:'1',installed:Array(201).fill({})}),/200/);
 const invalid=inventory();invalid.installed[0].metadata.requires_dist='bad';assert.throws(()=>parsePythonGraph(invalid),/requires_dist/);
});
test('Graph export includes resolved unconditional edges, not speculative optional dependencies',()=>{
 const graph=parsePythonGraph(inventory()),bom=graphSBOM(graph,'demo');assert.equal(bom.bomFormat,'CycloneDX');assert.deepEqual(bom.dependencies[0].dependsOn,['http-lib']);assert.equal(bom.components[0].purl,'pkg:pypi/app-client@1.0');
});
test('OpenAPI respects inherited authentication and explicit anonymous alternatives',()=>{
 const doc={openapi:'3.0.3',components:{securitySchemes:{bearer:{type:'http',scheme:'bearer'}}},security:[{bearer:[]}],paths:{'/private':{get:{responses:{}}},'/public':{get:{security:[]}},'/optional':{post:{security:[{bearer:[]},{}]}}}};
 const result=checkApplicationFiles([{path:'api.json',content:JSON.stringify(doc)}]);assert.equal(result.coverage.operations,3);assert.equal(result.findings.filter(f=>f.ruleId==='API001').length,2);assert.ok(!result.findings.some(f=>f.location==='GET /private'));
 doc.paths['/bad']={get:{security:[{missing:[]}]}};assert.ok(checkApplicationFiles([{path:'a.json',content:JSON.stringify(doc)}]).findings.some(f=>f.ruleId==='API002'));
});
test('OpenAPI invalid structures fail and unresolved references remain visible',()=>{
 assert.throws(()=>checkApplicationFiles([{path:'a.json',content:'{'}]),/Invalid JSON/);
 assert.throws(()=>checkApplicationFiles([{path:'a.json',content:JSON.stringify({openapi:'3.1.0',paths:{'/x':{get:{security:'bad'}}}})}]),/Invalid security/);
 const result=checkApplicationFiles([{path:'a.json',content:JSON.stringify({openapi:'3.0.3',paths:{'/x':{$ref:'elsewhere.json'}}})}]);assert.equal(result.warnings.length,1);
});
test('Container checks use final Dockerfile stage and normalized Compose settings',()=>{
 const docker={path:'Dockerfile',content:'FROM node:latest AS build\nUSER root\nFROM node:22\nUSER app\n'};
 const result=checkApplicationFiles([docker]);assert.ok(result.findings.some(f=>f.ruleId==='CTR001'));assert.ok(!result.findings.some(f=>f.ruleId==='CTR002'));
 const compose={path:'compose.json',content:JSON.stringify({services:{api:{privileged:true,volumes:[{source:'/var/run/docker.sock',target:'/sock'}]}}})};
 const checks=checkApplicationFiles([compose]);assert.equal(checks.findings.length,2);assert.ok(checks.findings.some(f=>f.severity==='Critical'));
 const inherited=checkApplicationFiles([{path:'Dockerfile',content:'FROM example@sha256:abc'}]);assert.match(inherited.findings[0].why,/unknown/);
});
test('Authentication patterns detect disabled validation, skip line comments, and preserve location',()=>{
 const result=checkApplicationFiles([{path:'auth.py',content:'# verify_signature: False\nclaims = jwt.decode(token, options={"verify_signature": False})\n'}]);assert.equal(result.findings.filter(f=>f.ruleId==='AUTH001').length,1);assert.equal(result.findings.find(f=>f.ruleId==='AUTH001').location,'2');
});
test('Priority index is deterministic and missing evidence cannot become a clean result',()=>{
 const missing=applicationAssessment({checks:emptyChecks()});assert.equal(missing.score,null);assert.equal(missing.decision,'REVIEW_REQUIRED');
 const app={graph:parsePythonGraph(inventory()),checks:checkApplicationFiles([{path:'compose.json',content:'{"services":{"x":{"privileged":true}}}'}]),advisories:{status:'complete',packages:[]}};
 const assessment=applicationAssessment(app);assert.equal(assessment.score,70);assert.equal(assessment.decision,'BLOCK');
 app.ai={summary:'Everything is safe',score:0};assert.equal(applicationAssessment(app).score,70);
 app.checks=emptyChecks();app.advisories={status:'partial',packages:[]};assert.equal(applicationAssessment(app).decision,'REVIEW_REQUIRED');
});
const jsonResponse=data=>({ok:true,text:async()=>JSON.stringify(data)});
const advisory={id:'GHSA-example',summary:'Example vulnerability',aliases:['CVE-EXAMPLE'],database_specific:{severity:'HIGH'},affected:[{package:{ecosystem:'PyPI',name:'http-lib'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.3'}]}]},{package:{ecosystem:'PyPI',name:'other'},ranges:[{events:[{fixed:'99'}]}]}]};
test('OSV sends only package identifiers and retrieves real protocol advisory details',async()=>{
 const calls=[];const osv=createOSVService({fetchImpl:async(url,options)=>{calls.push({url,options});return jsonResponse(url.endsWith('querybatch')?{results:[{vulns:[{id:advisory.id}]}]}:advisory);}});
 const result=await osv.lookup({consent:true,packages:[{name:'HTTP_Lib',version:'1.2',code:'must never be sent'}]});
 assert.equal(result.status,'complete');assert.equal(result.packages[0].advisories[0].severity,'High');assert.deepEqual(result.packages[0].advisories[0].fixedVersions,['1.3']);assert.ok(!calls[0].options.body.includes('must never be sent'));assert.deepEqual(JSON.parse(calls[0].options.body),{queries:[{package:{name:'http-lib',ecosystem:'PyPI'},version:'1.2'}]});
});
test('OSV requires consent before network and fails explicitly when offline',async()=>{
 let calls=0;const service=createOSVService({fetchImpl:async()=>{calls++;throw new Error('offline');}});
 await assert.rejects(service.lookup({consent:false,packages:[{name:'x',version:'1'}]}),/consent/);assert.equal(calls,0);
 await assert.rejects(service.lookup({consent:true,packages:[{name:'x',version:'1'}]}),/failed/);
});
test('OSV pagination is followed and unavailable details remain partial with unknown severity',async()=>{
 let batches=0;const service=createOSVService({fetchImpl:async(url,options)=>{
 if(url.endsWith('querybatch')){batches++;if(batches===1)return jsonResponse({results:[{vulns:[{id:'GHSA-one'}],next_page_token:'next'}]});assert.equal(JSON.parse(options.body).queries[0].page_token,'next');return jsonResponse({results:[{vulns:[{id:'GHSA-two'}]}]});}
 throw new Error('detail failed');
 }});
 const result=await service.lookup({consent:true,packages:[{name:'x',version:'1'}]});assert.equal(result.status,'partial');assert.equal(result.packages[0].advisories.length,2);assert.equal(result.packages[0].advisories[0].severity,'Unknown');
});
test('OSV removes withdrawn records and never fabricates severity from unsupported vectors',async()=>{
 const value=normalizeAdvisory({id:'x',severity:[{type:'CVSS_V4',score:'CVSS:4.0/example'}],affected:[]},{name:'x'});assert.equal(value.severity,'Unknown');assert.equal(value.cvss[0].vector,'CVSS:4.0/example');
 const service=createOSVService({fetchImpl:async url=>jsonResponse(url.endsWith('querybatch')?{results:[{vulns:[{id:'withdrawn'}]}]}:{id:'withdrawn',withdrawn:'2026-01-01'})});assert.equal((await service.lookup({consent:true,packages:[{name:'x',version:'1'}]})).packages[0].advisories.length,0);
});
const review=()=>({summary:'Review authentication and container configuration.',confidence:'medium',relationships:[{evidenceIds:['finding-1','scope'],hypothesis:'The source and container may belong to the same deployed service.',validationNeeded:'Confirm deployment mapping and test authorization.'}],actions:[{evidenceIds:['finding-1'],action:'Review the privileged setting.',verification:'Inspect the deployed configuration.'}],unknowns:['Runtime exposure has not been tested.']});
test('AI application evidence excludes raw files and retains coverage and known unknowns',()=>{
 const app={graph:parsePythonGraph(inventory()),checks:checkApplicationFiles([{path:'compose.json',content:'{"services":{"api":{"privileged":true}}}'}])};
 const {records}=applicationEvidence(app);assert.ok(records.some(r=>r.id==='scope'));assert.ok(records.some(r=>r.id==='limitations'));
 const prepared=prepareApplicationReview({model:'qwen2.5-coder:3b',records});assert.equal(prepared.contextHash.length,64);
 const result=validateApplicationReview(review(),records);assert.equal(result.relationships[0].status,'unverified_hypothesis');
 const invalid=review();invalid.actions[0].evidenceIds=['invented'];assert.throws(()=>validateApplicationReview(invalid,records),/not supplied/);
});
test('Application AI calls local model with evidence and rejects malformed output',async()=>{
 const records=[{id:'scope',source:'coverage',detail:'runtime not tested'},{id:'finding-1',source:'compose.json',detail:'privileged true'}];let body;
 const service=createAIService({fetchImpl:async(url,options)=>({ok:true,json:async()=>url.endsWith('/api/tags')?{models:[{name:'qwen2.5-coder:3b',size:1900000000,details:{format:'gguf'}}]}:(body=JSON.parse(options.body),{done:true,message:{content:JSON.stringify(review())}})})});
 const result=await service.review({model:'qwen2.5-coder:3b',records});assert.equal(result.metadata.promptVersion,'application-evidence-v1');assert.equal(body.format.type,'object');assert.ok(body.messages[0].content.includes('HYPOTHESES'));assert.equal(result.evidence.length,2);
});
import {mountApplication} from '../dist/application-ui.js';
test('Application controller loads real demo checks and persists a review without model or network',async()=>{
 const handlers={},state={applicationReviews:[]};let persisted=0,events=0;
 const root={isConnected:true,innerHTML:'',addEventListener(type,fn){handlers[type]=fn;},querySelectorAll(){return [];}};
 mountApplication(root,{state,persist(){persisted++;},log(){events++;}});
 assert.ok(root.innerHTML.includes('Build application review'));
 await handlers.click({target:{closest(selector){return selector==='[data-app-action]'?{dataset:{appAction:'demo'}}:null;}}});
 assert.equal(state.applicationReviews.length,1);assert.equal(state.applicationReviews[0].graph.nodes.length,3);assert.ok(root.innerHTML.includes('Python dependency graph'));assert.ok(root.innerHTML.includes('JWT signature verification appears disabled'));assert.ok(root.innerHTML.includes('Docker socket mounted into container'));assert.equal(state.applicationReviews[0].ai,null);assert.equal(state.applicationReviews[0].advisories,null);assert.equal(persisted,1);assert.equal(events,1);
});
