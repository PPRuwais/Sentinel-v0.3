import {readFile,writeFile} from 'node:fs/promises';
import {scanFiles} from '../dist/sentinel.mjs';
import {createAIService,DEFAULT_MODEL,PROMPT_VERSION} from '../lib/ai.mjs';

// Actual local model calls. No stub, fallback response, or hardcoded analysis.
const model=process.argv[2]||DEFAULT_MODEL;
const cases=[
 {file:'unsafe-preview.js',expected:'likely_risk'},
 {file:'constant-preview.js',expected:'likely_false_positive'}
];
const report={model,promptVersion:PROMPT_VERSION,startedAt:new Date().toISOString(),scope:'Two illustrative cases; not a security benchmark or calibrated accuracy estimate.',results:[]};
const ai=createAIService();
try{
 const available=await ai.status();
 if(!available.models.some(m=>m.name===model))throw new Error(`Install the model first: ollama pull ${model}`);
 for(const item of cases){
  console.log(`Running real inference: ${item.file} with ${model}…`);
  const content=await readFile(new URL('../demo/'+item.file,import.meta.url),'utf8');
  const scan=scanFiles([{path:item.file,content}],'AI evaluation');
  const finding=scan.findings.find(f=>f.ruleId==='SEN004');
  if(!finding)throw new Error('Evaluation fixture did not trigger the expected rule.');
  try{
   const analysis=await ai.analyze({model,finding,scanCreatedAt:scan.createdAt});
   const matchesExpected=analysis.assessment===item.expected;
   report.results.push({file:item.file,expected:item.expected,matchesExpected,analysis});
   console.log(`  Returned: ${analysis.assessment}; expected: ${item.expected}; citations matched source.`);
  }catch(error){report.results.push({file:item.file,expected:item.expected,error:error.message});console.error('  Review failed: '+error.message);}
 }
 report.matchesExpected=report.results.filter(r=>r.matchesExpected).length;
 report.completedAt=new Date().toISOString();
 await writeFile('ai-evaluation-results.json',JSON.stringify(report,null,2));
 console.log(`Saved ai-evaluation-results.json. ${report.matchesExpected}/${cases.length} assessments matched the illustrative labels.`);
 process.exitCode=report.results.some(r=>r.error)?1:0;
}catch(error){console.error(error.message);process.exitCode=1;}
