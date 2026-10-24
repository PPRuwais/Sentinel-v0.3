import {writeFile} from 'node:fs/promises';
import {demoFiles} from '../dist/application-ui.js';
import {parsePythonGraph,checkApplicationFiles,applicationAssessment,applicationEvidence} from '../dist/application-core.mjs';
import {createOSVService} from '../lib/osv.mjs';
import {createAIService,DEFAULT_MODEL} from '../lib/ai.mjs';
// Explicit live check: only the constructed sample package names/versions go to OSV.
const model=process.argv[2]||DEFAULT_MODEL;
const app={name:'Live application pipeline check',demo:true,graph:parsePythonGraph(JSON.parse(demoFiles[0].content)),checks:checkApplicationFiles(demoFiles)};
try{
 console.log('Sending constructed sample package names and versions to api.osv.dev…');
 app.advisories=await createOSVService().lookup({consent:true,packages:app.graph.nodes.map(n=>({name:n.name,version:n.version}))});
 console.log('OSV status:',app.advisories.status);
 console.log('Requesting actual local model review:',model);
 app.ai=await createAIService().review({model,records:applicationEvidence(app).records});
 app.assessment=applicationAssessment(app);
 await writeFile('application-live-results.json',JSON.stringify(app,null,2));
 console.log('Saved actual responses to application-live-results.json. Review the model reasoning and hypotheses manually.');
 if(app.advisories.status!=='complete')process.exitCode=1;
}catch(error){app.error=error.message;await writeFile('application-live-results.json',JSON.stringify(app,null,2));console.error(error.message);process.exitCode=1;}
