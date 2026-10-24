import test from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {scanFiles,redactSource,buildContext,verifySuggestedFix,decision} from '../dist/sentinel.mjs';
import {prepareRequest,validateAnalysis,createAIService,SYSTEM_PROMPT,PROMPT_VERSION} from '../lib/ai.mjs';
import {createHandler,checkLocalRequest} from '../server.mjs';
const code='function preview(req, element) {\n  const userInput = req.body.content;\n  element.innerHTML = userInput;\n}';
const scan=scanFiles([{path:'preview.js',content:code}],'demo');
const finding=scan.findings[0];
const input={model:'qwen2.5-coder:3b',scanCreatedAt:scan.createdAt,finding};
const valid=()=>({assessment:'likely_risk',confidence:'high',summary:'Request content reaches an HTML sink.',explanation:'The supplied handler assigns a request body value to innerHTML without a visible sanitizer.',evidence:[{line:2,quote:'req.body.content',reason:'Visible request input.'},{line:3,quote:'element.innerHTML = userInput;',reason:'HTML sink.'}],assumptions:['Upstream validation is not shown.'],fix:{explanation:'If plain text is intended, use textContent.',before:'element.innerHTML = userInput;',after:'element.textContent = userInput;'},verificationSteps:['Submit markup and verify that it renders as text.','Run application tests and rescan the complete source.']});
const tags={models:[{name:input.model,size:1900000000,digest:'test-digest',details:{format:'gguf',parameter_size:'3B'}}]};
const reply=body=>({ok:true,json:async()=>body});
test('context extraction preserves line numbers and redacts before prompt preparation',()=>{
 const source='const api_key = "sensitive-test-credential";\nconst token = "ghp_abcdefghijklmnopqrstuvwxyz";\nelement.innerHTML = input;';
 const f=scanFiles([{path:'a.js',content:source}]).findings.find(f=>f.ruleId==='SEN004');
 const request=prepareRequest({finding:f,model:input.model});
 assert.ok(!JSON.stringify(f).includes('sensitive-test-credential'));
 assert.ok(!request.userMessage.includes('abcdefghijklmnopqrstuvwxyz'));
 assert.ok(request.userMessage.includes('[REDACTED]'));
 assert.equal(f.context.startLine,1);assert.equal(f.line,3);
 assert.match(SYSTEM_PROMPT,/UNTRUSTED DATA/);
});
test('private keys are redacted without shifting later line references',()=>{
 const source='-----BEGIN RSA PRIVATE KEY-----\nsecretbytes\n-----END RSA PRIVATE KEY-----\neval(input)';
 const r=redactSource(source);assert.ok(!r.content.includes('secretbytes'));assert.equal(r.content.split('\n').length,4);
 const f=scanFiles([{path:'x.js',content:source}]).findings[0];assert.equal(f.line,4);
});
test('bounded context includes flagged line in large files',()=>{
 const c=buildContext(Array.from({length:100},(_,i)=>'line '+(i+1)).join('\n'),55);
 assert.equal(c.startLine,37);assert.equal(c.endLine,73);assert.equal(c.truncated,true);assert.ok(c.content.includes('line 55'));
 const huge=buildContext('x'.repeat(18000),1);assert.equal(huge.content.length,10000);assert.equal(huge.truncated,true);
});
test('rejects absent context, unknown rules, out-of-range locations and cloud models',()=>{
 for(const bad of [{finding:{...finding,context:null}},{finding:{...finding,ruleId:'fake'}},{finding:{...finding,line:999}},{...input,model:'model:cloud'},{...input,model:'https://remote.invalid'}])assert.throws(()=>prepareRequest(bad));
});
test('validates actual citations and rejects invented evidence and unmatched replacement',()=>{
 const p=prepareRequest(input);assert.equal(validateAnalysis(valid(),p).assessment,'likely_risk');
 const invented=valid();invented.evidence[0].quote='not in the source';assert.throws(()=>validateAnalysis(invented,p),/does not match/);
 const wrongLine=valid();wrongLine.evidence[1].line=99;assert.throws(()=>validateAnalysis(wrongLine,p),/does not match/);
 const missingFlag=valid();missingFlag.evidence=[missingFlag.evidence[0]];assert.throws(()=>validateAnalysis(missingFlag,p),/flagged line/);
 const badPatch=valid();badPatch.fix.before='fictional()';assert.throws(()=>validateAnalysis(badPatch,p),/replacement does not match/);
 const changed=prepareRequest({...input,finding:{...finding,context:{...finding.context,content:code+'\n// new'}}});assert.notEqual(p.contextHash,changed.contextHash);
});
test('service sends context to fixed local endpoint and records real response metadata',async()=>{
 const calls=[];const ai=createAIService({fetchImpl:async(url,options)=>{calls.push({url,options});return reply(url.endsWith('/api/tags')?tags:{done:true,done_reason:'stop',message:{content:JSON.stringify(valid())},prompt_eval_count:120,eval_count:200});}});
 const output=await ai.analyze(input);assert.equal(calls.length,2);assert.equal(calls[1].url,'http://127.0.0.1:11434/api/chat');
 const body=JSON.parse(calls[1].options.body);assert.equal(body.stream,false);assert.equal(body.format.type,'object');assert.equal(body.messages[0].content,SYSTEM_PROMPT);assert.ok(body.messages[1].content.includes('req.body.content'));
 assert.equal(output.metadata.promptVersion,PROMPT_VERSION);assert.equal(output.metadata.inputTokens,120);assert.equal(output.metadata.model,input.model);assert.match(output.metadata.contextHash,/^[a-f0-9]{64}$/);
});
test('unavailable service, missing model and malformed output fail without fabricated analysis',async()=>{
 await assert.rejects(createAIService({fetchImpl:async()=>{throw new Error('offline');}}).analyze(input),/Cannot reach Ollama/);
 await assert.rejects(createAIService({fetchImpl:async()=>reply({models:[]})}).analyze(input),/not installed/);
 for(const response of [{done:true,message:{content:'not JSON'}},{done:false,message:{content:JSON.stringify(valid())}},{done:true,done_reason:'length',message:{content:JSON.stringify(valid())}}]){
  const ai=createAIService({fetchImpl:async url=>reply(url.endsWith('/api/tags')?tags:response)});await assert.rejects(ai.analyze(input));
 }
});
test('model list excludes cloud, tiny stubs, and non-GGUF entries',async()=>{
 const ai=createAIService({fetchImpl:async()=>reply({models:[...tags.models,{...tags.models[0],name:'remote:cloud'},{...tags.models[0],remote_host:'https://remote'},{...tags.models[0],size:100},{...tags.models[0],details:{}}]})});assert.equal((await ai.status()).models.length,1);
});
test('AI suggestion check runs heuristics only and never changes finding or release gate',()=>{
 const saved=JSON.stringify(finding),gate=decision(scan).decision;
 const check=verifySuggestedFix(finding,valid().fix);
 assert.equal(check.ruleBefore,1);assert.equal(check.ruleAfter,0);assert.equal(JSON.stringify(finding),saved);assert.equal(decision(scan).decision,gate);
 assert.throws(()=>verifySuggestedFix(finding,{before:'missing',after:'other'}));
 assert.throws(()=>verifySuggestedFix(finding,{before:'[REDACTED]',after:'other'}));
});
test('server rejects foreign origins, DNS rebinding hosts, and non-JSON requests',()=>{
 const valid={method:'POST',headers:{host:'localhost:3000',origin:'http://localhost:3000','content-type':'application/json'}};
 assert.doesNotThrow(()=>checkLocalRequest(valid,3000));
 for(const headers of [{...valid.headers,host:'attacker.invalid:3000'},{...valid.headers,origin:'https://attacker.invalid'},{...valid.headers,'content-type':'text/plain'},{...valid.headers,origin:undefined}])assert.throws(()=>checkLocalRequest({...valid,headers},3000));
});
async function invoke(handler,{body=input,origin='http://localhost:3000',url='/api/ai/analyze',method='POST',raw}={}){
 const req=Readable.from([Buffer.from(raw??JSON.stringify(body))]);req.url=url;req.method=method;req.headers={host:'localhost:3000',origin,'content-type':'application/json'};
 const res={status:0,body:'',writeHead(status,headers){this.status=status;this.headers=headers;return this;},end(data){this.body=data?.toString()||'';this.writableEnded=true;return this;}};
 await handler(req,res);return res;
}
test('HTTP handler rejects bad bodies before calling inference and serves success',async()=>{
 let count=0;const handler=createHandler({ai:{analyze:async data=>{count++;return {assessment:'needs_review',received:data.model};},status:async()=>({connected:true,models:[]})}});
 assert.equal((await invoke(handler,{raw:'bad json'})).status,400);assert.equal(count,0);
 assert.equal((await invoke(handler,{raw:'x'.repeat(40001)})).status,413);assert.equal(count,0);
 assert.equal((await invoke(handler,{origin:'https://attacker.invalid'})).status,403);assert.equal(count,0);
 const ok=await invoke(handler);assert.equal(ok.status,200);assert.equal(JSON.parse(ok.body).received,input.model);assert.equal(count,1);
 const status=await invoke(handler,{url:'/api/ai/status',method:'GET'});assert.equal(status.status,200);
});
test('server allows only one AI inference at a time and releases lock after failure',async()=>{
 let release;const handler=createHandler({ai:{analyze:()=>new Promise(resolve=>release=resolve)}});
 const first=invoke(handler);while(!release)await new Promise(resolve=>setImmediate(resolve));
 assert.equal((await invoke(handler)).status,429);release({assessment:'needs_review'});assert.equal((await first).status,200);
 const failing=createHandler({ai:{analyze:async()=>{throw new Error('failed');}}});assert.equal((await invoke(failing)).status,500);assert.equal((await invoke(failing)).status,500);
});
