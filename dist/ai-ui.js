import {verifySuggestedFix} from './sentinel.mjs';
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const list=items=>`<ul>${items.map(x=>`<li>${escape(x)}</li>`).join('')}</ul>`;
let activeJob=false;
function savedModel(){try{return localStorage.getItem('sentinel-ai-model')||'qwen2.5-coder:3b';}catch{return 'qwen2.5-coder:3b';}}
function saveModel(model){try{localStorage.setItem('sentinel-ai-model',model);}catch{}}
async function api(path,options={}){
  const response=await fetch(path,{...options,headers:{'Content-Type':'application/json',...options.headers},signal:AbortSignal.timeout(250000)});
  let data;try{data=await response.json();}catch{throw new Error('The AI server is unavailable. Stop the old app and start server.mjs from the new Sentinel AI folder.');}
  if(!response.ok)throw new Error(data.error||`Request failed (${response.status}).`);
  return data;
}
function errorMessage(error){return ['TimeoutError','AbortError'].includes(error.name)?'The request timed out. Let the local model finish, then try a smaller model.':error.message||'Could not contact the local AI service.';}
function resultHTML(finding){
  const a=finding.ai;if(!a)return '';
  const labels={likely_risk:'Likely risk',likely_false_positive:'Possible false positive',needs_review:'Needs more context'};
  return `<div class="ai-result"><div class="ai-result-head"><span class="badge neutral">${labels[a.assessment]||escape(a.assessment)}</span><span>Model confidence: ${escape(a.confidence)} · not a probability</span></div><h3>${escape(a.summary)}</h3><p>${escape(a.explanation)}</p><h4>Evidence in your code</h4>${a.evidence.map(e=>`<div class="ai-evidence"><strong>Line ${e.line}</strong><code>${escape(e.quote)}</code><p>${escape(e.reason)}</p></div>`).join('')}<h4>Assumptions & missing context</h4>${a.assumptions.length?list(a.assumptions):'<p>No additional assumptions listed by the model. Review the excerpt scope.</p>'}<h4>Suggested fix · untested</h4><p>${escape(a.fix.explanation)}</p>${a.fix.before?`<label>Replace this excerpt<pre class="code">${escape(a.fix.before)}</pre></label><label>With this suggestion<pre class="code">${escape(a.fix.after)}</pre></label><div class="ai-action-row"><button class="btn" data-ai="copy">Copy suggested code</button><button class="btn" data-ai="verify">Check with scanner</button></div>`:'<p>The model did not provide an exact replacement. Review its guidance manually.</p>'}<div data-ai-verification>${verificationHTML(finding)}</div><h4>How to verify the change</h4>${list(a.verificationSteps)}<details class="ai-provenance"><summary>Analysis provenance & export</summary><p>Model: ${escape(a.metadata.model)}<br>Generated: ${escape(a.metadata.generatedAt)}<br>Prompt: ${escape(a.metadata.promptVersion)}<br>Inference request: ${(a.metadata.durationMs/1000).toFixed(1)} seconds<br>Tokens: ${a.metadata.inputTokens??'unknown'} input / ${a.metadata.outputTokens??'unknown'} output</p><code>Context SHA-256: ${escape(a.metadata.contextHash)}</code><p>${escape(a.metadata.citationCheck)}</p><button class="btn" data-ai="download">Download AI review JSON</button></details><p class="note">${escape(a.disclaimer)}</p></div>`;
}
function verificationHTML(f){
 const v=f.ai?.verification;if(!v)return '';
 return `<div class="note" style="margin-top:12px"><strong>Excerpt check: ${v.ruleBefore} → ${v.ruleAfter} matches for ${escape(f.ruleId)}</strong><br>Total rule matches: ${v.before} → ${v.after}.<br>${escape(v.scope)}</div>`;
}
export function mountAIReview(root,{finding,scanCreatedAt,onSave,onAudit}){
  if(!root)return;
  root.innerHTML=`<section class="ai-review"><div class="ai-heading"><div><span class="eyebrow">LOCAL MODEL · CONTEXTUAL REVIEW</span><h3>AI security analyst</h3></div><span class="badge neutral">Ollama</span></div><p>Review this finding with a local model. Citations are checked against the excerpt; AI does not change your triage or release gate.</p>${finding.context?`<details class="ai-context"><summary>Preview the context sent to AI · lines ${finding.context.startLine}–${finding.context.endLine}</summary><p>${finding.context.truncated?'Bounded excerpt: other code may be missing.':'All lines of this small file are included.'} Credential-like values are filtered; redaction is best effort. This redacted excerpt is stored with the finding.</p><pre class="code">${escape(finding.context.content.split('\n').map((l,i)=>`${finding.context.startLine+i}  ${l}`).join('\n'))}</pre></details>`:'<p class="note">This finding predates AI context capture. Rescan the project in this version to enable AI review.</p>'}<div class="ai-action-row"><button class="btn" data-ai="connect">Check Ollama</button><select class="small-select" aria-label="Local AI model" data-ai-model disabled><option>Check connection first</option></select><button class="btn primary" data-ai="analyze" disabled>Analyze with AI</button></div><p class="ai-status" role="status" aria-live="polite">Install Ollama, then run: <code>ollama pull qwen2.5-coder:3b</code></p><div data-ai-result>${resultHTML(finding)}</div></section>`;
  const status=root.querySelector('.ai-status'),model=root.querySelector('[data-ai-model]'),analyzeButton=root.querySelector('[data-ai="analyze"]'),connect=root.querySelector('[data-ai="connect"]');
  root.addEventListener('click',async event=>{
    const action=event.target.closest('[data-ai]')?.dataset.ai;if(!action)return;event.preventDefault();
    if(action==='connect'){
      connect.disabled=true;status.textContent='Checking the local Ollama service…';
      try{const data=await api('/api/ai/status');if(!data.models.length)throw new Error('Ollama is running, but no local GGUF model was found. Run ollama pull qwen2.5-coder:3b, then check again.');model.innerHTML=data.models.map(m=>`<option value="${escape(m.name)}">${escape(m.name)}${m.parameters?' · '+escape(m.parameters):''}</option>`).join('');if(data.models.some(m=>m.name===savedModel()))model.value=savedModel();model.disabled=false;analyzeButton.disabled=!finding.context;status.textContent='Connected to local Ollama. Preview the context, select a model, then analyze.';}catch(error){status.textContent=errorMessage(error);model.disabled=true;analyzeButton.disabled=true;}finally{connect.disabled=false;}return;
    }
    if(action==='analyze'){
      if(activeJob){status.textContent='Another review is running. Wait for it to finish.';return;}
      activeJob=true;analyzeButton.disabled=true;connect.disabled=true;model.disabled=true;saveModel(model.value);
      status.textContent='Generating a real local-model review… The first request can take several minutes while the model loads.';
      try{const result=await api('/api/ai/analyze',{method:'POST',body:JSON.stringify({model:model.value,scanCreatedAt,finding:{ruleId:finding.ruleId,path:finding.path,line:finding.line,context:finding.context}})});finding.ai=result;onSave();onAudit('AI review completed',`${finding.project} · ${finding.ruleId} · ${result.metadata.model}`);if(root.isConnected){root.querySelector('[data-ai-result]').innerHTML=resultHTML(finding);status.textContent='AI review saved. Source quotes matched; assess the reasoning and test any suggested fix.';}}catch(error){if(root.isConnected)status.textContent=errorMessage(error);onAudit('AI review failed',`${finding.project} · ${finding.ruleId} · no new review saved`);}finally{activeJob=false;if(root.isConnected){analyzeButton.disabled=false;connect.disabled=false;model.disabled=false;}}return;
    }
    if(action==='copy'){
      try{await navigator.clipboard.writeText(finding.ai.fix.after);status.textContent='Suggested code copied. Review and test before applying.';}catch{status.textContent='Select the suggested code above and copy it manually.';}return;
    }
    if(action==='verify'){
      try{finding.ai.verification=verifySuggestedFix(finding,finding.ai.fix);onSave();onAudit('AI suggestion checked',`${finding.project} · ${finding.ruleId} · excerpt-only heuristic rescan`);root.querySelector('[data-ai-verification]').innerHTML=verificationHTML(finding);status.textContent='Checked against the same scanner rules. Your source and release gate have not changed.';}catch(error){status.textContent=error.message;}return;
    }
    if(action==='download'){
      const data={project:finding.project,ruleId:finding.ruleId,path:finding.path,line:finding.line,context:finding.context,analysis:finding.ai};const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const link=document.createElement('a');link.href=url;link.download='sentinel-ai-review.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);onAudit('AI review exported',`${finding.project} · ${finding.ruleId}`);return;
    }
  });
}
export function mountAISettings(root){
 if(!root)return;
 root.innerHTML=`<div class="card ai-settings"><h2>Local AI analysis</h2><p>Sentinel sends bounded, redacted code context through its local server to Ollama on this PC. No API key is required. Local GGUF models are supported; cloud model tags are excluded.</p><ol><li>Install and open <a href="https://ollama.com/download" target="_blank" rel="noopener noreferrer">Ollama</a>.</li><li>In a terminal, run <code>ollama pull qwen2.5-coder:3b</code>.</li><li>Open a finding → AI security analyst → Check Ollama → Analyze with AI.</li></ol><button class="btn" data-ai-check>Check AI connection</button><p class="ai-status" role="status" aria-live="polite"></p><p class="note">Model files are downloaded separately. For a lighter model use qwen2.5-coder:1.5b. For stronger reasoning, use qwen2.5-coder:7b if your PC has enough memory. AI may be wrong; it never changes policy or triage automatically.</p></div>`;
 root.querySelector('[data-ai-check]').addEventListener('click',async e=>{e.target.disabled=true;const status=root.querySelector('.ai-status');status.textContent='Checking Ollama…';try{const data=await api('/api/ai/status');status.textContent=data.models.length?'Connected. Local models: '+data.models.map(m=>m.name).join(', '):'Ollama connected. Download a model, then check again.';}catch(error){status.textContent=errorMessage(error);}finally{e.target.disabled=false;}});
}
