/** Sentinel: a small, local-first heuristic source scanner. No network requests. */
export const rules = [
 {id:'SEN001',title:'Potential SQL injection',severity:'Critical',category:'Source code',re:/\b(?:query|execute)\s*\([^\n]*(?:\+\s*(?:req\.|request\.|user|input)|\$\{)/i,cwe:'CWE-89',why:'Untrusted values appear to be concatenated into a database query. An attacker may change the query structure and access or modify data.',fix:'Use parameterized queries and bind user input separately. Example: db.query("SELECT * FROM users WHERE id = ?", [req.params.id]).'},
 {id:'SEN002',title:'Hardcoded credential',severity:'Critical',category:'Secrets',re:/(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*["'][^"'\n]{8,}["']/i,cwe:'CWE-798',why:'A credential-like value is stored in source. If it is real, anyone with access to the repository or build artifacts may be able to use it.',fix:'Revoke and rotate any real exposed credential. Load its replacement from a secret manager or environment variable and remove it from repository history.'},
 {id:'SEN003',title:'Dynamic code execution',severity:'High',category:'Source code',re:/\beval\s*\(/,cwe:'CWE-95',why:'eval executes strings as code. If an untrusted value reaches this call, it may allow arbitrary code execution.',fix:'Replace eval with a data parser such as JSON.parse, or an explicit allowlisted operation map. Verify the input data flow.'},
 {id:'SEN004',title:'Unsafe HTML assignment',severity:'High',category:'Source code',re:/\.innerHTML\s*=/,cwe:'CWE-79',why:'Assigning strings to innerHTML can execute attacker-controlled markup when input is not trusted or sanitized.',fix:'Use textContent for plain text. If HTML is required, use a maintained HTML sanitizer and validate the input boundary.'},
 {id:'SEN005',title:'TLS verification disabled',severity:'High',category:'Configuration',re:/(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0)/,cwe:'CWE-295',why:'Disabling certificate verification can let an intermediary impersonate a trusted service.',fix:'Enable certificate verification and configure the correct trusted CA certificate.'},
 {id:'SEN006',title:'Unpinned container image',severity:'Medium',category:'Container',re:/^\s*FROM\s+[^\s]+:latest\b/i,cwe:'CWE-1104',why:'The latest tag is mutable. Rebuilding the same source can produce a different image and dependency set.',fix:'Pin a supported image version and digest. Update it on a regular, reviewed schedule.'},
 {id:'SEN007',title:'Privileged container user',severity:'Medium',category:'Container',re:/^\s*USER\s+(?:root|0)\s*$/i,cwe:'CWE-250',why:'The image explicitly runs as root, increasing the impact of a compromise inside the container.',fix:'Create a dedicated unprivileged user and switch to it with USER before the application entrypoint.'},
 {id:'SEN008',title:'Debug mode enabled',severity:'Low',category:'Configuration',re:/\b(?:DEBUG\s*=\s*True|debug\s*:\s*true)\b/,cwe:'CWE-489',why:'Debug output may reveal internal details if this setting reaches production.',fix:'Disable debug mode in production configuration and ensure error responses do not expose stack traces.'}
];
// Context is bounded and redacted before storage or AI review; this is not a complete DLP system.
export function redactSource(source) {
 let redactions=0;
 let content=String(source).replace(/-----BEGIN [^\n]*PRIVATE KEY-----[\s\S]*?-----END [^\n]*PRIVATE KEY-----/g,match=>{redactions++;return match.split('\n').map(()=> '[REDACTED PRIVATE KEY]').join('\n');});
 content=content.replace(/((?:api[_-]?key|secret|password|access[_-]?token|authorization)\s*["']?\s*[:=]\s*)(["'`])([^\n]*?)\2/gi,(match,prefix,quote,value)=>{if(value==='[REDACTED]')return match;redactions++;return prefix+quote+'[REDACTED]'+quote;});
 content=content.replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,()=>{redactions++;return '[REDACTED]';});
 return {content,redactions};
}
export function buildContext(source,line,prepared=null) {
 const redacted=prepared||redactSource(source),rows=redacted.rows||redacted.content.split('\n');
 let start=Math.max(0,line-19),end=Math.min(rows.length,line+18);
 while(rows.slice(start,end).join('\n').length>10000&&end-start>1){if(line-1-start>=end-line)start++;else end--;}
 const content=rows.slice(start,end).map(row=>row.length>10000?row.slice(0,10000):row).join('\n');
 return {startLine:start+1,endLine:end,totalLines:rows.length,content,truncated:start>0||end<rows.length||rows.slice(start,end).some(r=>r.length>10000),redactions:redacted.redactions};
}
export function verifySuggestedFix(finding,fix) {
 const ctx=finding.context;
 if(!ctx?.content||!fix?.before||!fix?.after)throw new Error('No exact replacement is available to check.');
 if(fix.before.includes('[REDACTED')||fix.after.includes('[REDACTED'))throw new Error('This replacement contains redacted values. Edit and review the real source manually.');
 const first=ctx.content.indexOf(fix.before);
 if(first<0||ctx.content.indexOf(fix.before,first+1)!==-1)throw new Error('Replacement must match exactly once in the captured excerpt.');
 const changed=ctx.content.slice(0,first)+fix.after+ctx.content.slice(first+fix.before.length);
 const before=scanFiles([{path:finding.path,content:ctx.content}]).findings;
 const after=scanFiles([{path:finding.path,content:changed}]).findings;
 return {checkedAt:new Date().toISOString(),scope:'Captured excerpt only; code was not executed, syntax-checked, or tested. Original files and release gate are unchanged.',before:before.length,after:after.length,ruleBefore:before.filter(f=>f.ruleId===finding.ruleId).length,ruleAfter:after.filter(f=>f.ruleId===finding.ruleId).length,remaining:after.map(f=>({ruleId:f.ruleId,severity:f.severity,line:ctx.startLine+f.line-1}))};
}
export function scanFiles(files,project='Untitled project') {
 const findings=[],components=[];let lines=0;
 for(const file of files){const content=file.content||''; const rows=content.split('\n'); lines+=rows.length;const safe=redactSource(content);safe.rows=safe.content.split('\n');
 rows.forEach((line,i)=>{for(const rule of rules)if(rule.re.test(line))findings.push({id:`${rule.id}:${file.path}:${i+1}`,ruleId:rule.id,title:rule.title,severity:rule.severity,category:rule.category,cwe:rule.cwe,path:file.path,line:i+1,excerpt:rule.category==='Secrets'?'[Credential-like value redacted]':redactSource(line).content.trim().slice(0,300),context:buildContext(content,i+1,safe),why:rule.why,fix:rule.fix,status:'Open',project});});
 if(/(?:^|\/)package(?:-lock)?\.json$/.test(file.path))try{const p=JSON.parse(content);if(p.packages){for(const [name,v]of Object.entries(p.packages))if(name&&v.version)components.push({type:'library',name:name.replace(/^.*node_modules\//,''),version:v.version});}else for(const [name,version]of Object.entries({...p.dependencies,...p.devDependencies}))components.push({type:'library',name,version:String(version)});}catch{}
 }
 return {project,createdAt:new Date().toISOString(),files:files.length,lines,findings,components:[...new Map(components.map(c=>[c.name+'@'+c.version,c])).values()],engine:'Sentinel heuristic scanner 0.2',limitations:'Pattern-based checks only. Findings require review; no CVE database, reachability analysis, live URL testing, or automatic AI inference. Optional dashboard AI reviews are separate.'};
}
export function sarif(scan){return {$schema:'https://json.schemastore.org/sarif-2.1.0.json',version:'2.1.0',runs:[{tool:{driver:{name:'Sentinel',version:'0.1.0',rules:rules.map(r=>({id:r.id,shortDescription:{text:r.title},help:{text:r.fix}}))}},results:scan.findings.map(f=>({ruleId:f.ruleId,level:['Critical','High'].includes(f.severity)?'error':f.severity==='Medium'?'warning':'note',message:{text:f.title},locations:[{physicalLocation:{artifactLocation:{uri:f.path.replaceAll('\\','/')},region:{startLine:f.line}}}]}))}]};}
export function sbom(scan){return {bomFormat:'CycloneDX',specVersion:'1.5',version:1,metadata:{timestamp:scan.createdAt,component:{type:'application',name:scan.project}},components:scan.components};}
export function decision(scan,policy={blockCritical:true,blockHigh:true}){const blockers=scan.findings.filter(f=>f.status==='Open'&&((policy.blockCritical&&f.severity==='Critical')||(policy.blockHigh&&f.severity==='High')));return {decision:blockers.length?'BLOCK':'PASS',blockers:blockers.length,policy,evaluatedAt:new Date().toISOString(),scope:'Supported heuristic checks only; PASS is not an assurance of security.'};}
if(typeof process!=='undefined'&&process.versions?.node&&process.argv[1]&&import.meta.url===(await import('node:url')).pathToFileURL(process.argv[1]).href){
 const fs=await import('node:fs/promises'),path=await import('node:path');const args=process.argv.slice(2);if(args[0]!=='scan'){console.log('Sentinel • local-first source scanner\nUsage: node sentinel.mjs scan <directory> [--format json|sarif|sbom]');process.exit(0);}const root=path.resolve(args[1]||'.'),files=[];let skipped=0;
 async function walk(dir){for(const e of await fs.readdir(dir,{withFileTypes:true})){if(['node_modules','.git','dist','build','.next'].includes(e.name)||e.isSymbolicLink())continue;const p=path.join(dir,e.name);if(e.isDirectory())await walk(p);else if(/\.(?:js|jsx|ts|tsx|py|json|yml|yaml|env|txt|sh)$/.test(e.name)||/^(Dockerfile|\.env)/.test(e.name)){if((await fs.stat(p)).size>1000000){skipped++;continue;}files.push({path:path.relative(root,p),content:await fs.readFile(p,'utf8')});}}}
 try{await walk(root);if(!files.length)throw new Error('No supported source files found.');const result=scanFiles(files,path.basename(root)),format=args[args.indexOf('--format')+1];if(args.includes('--format')&&!['json','sarif','sbom'].includes(format))throw new Error('Unsupported format. Choose json, sarif, or sbom.');console.log(JSON.stringify(format==='sarif'?sarif(result):format==='sbom'?sbom(result):{...result,policy:decision(result),skipped},null,2));process.exitCode=decision(result).decision==='BLOCK'?1:0;}catch(e){console.error('Scan failed: '+e.message);process.exitCode=2;}
}
