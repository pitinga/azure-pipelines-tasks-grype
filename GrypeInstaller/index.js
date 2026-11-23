'use strict';
const os=require('node:os');
const path=require('node:path');
const ado=require('./lib/ado');
const {installTool}=require('./lib/installer');
const {execute}=require('./lib/cli');
async function main(){try{
 const cacheRoot=process.env.AGENT_TOOLSDIRECTORY||process.env.RUNNER_TOOL_CACHE||path.join(os.homedir(),'.grype-task-tools');
 const grype=await installTool('grype',ado.input('grypeVersion','latest'),cacheRoot);
 const syft=await installTool('syft',ado.input('syftVersion','latest'),cacheRoot);
 await execute(grype.binary,['version']);
 await execute(syft.binary,['version']);
 ado.prependPath(path.dirname(grype.binary));ado.prependPath(path.dirname(syft.binary));
 ado.setVariable('GRYPE_PATH',grype.binary);ado.setVariable('GRYPE_VERSION',grype.version);
 ado.setVariable('SYFT_PATH',syft.binary);ado.setVariable('SYFT_VERSION',syft.version);
 ado.complete(`Grype ${grype.version} e Syft ${syft.version} instalados para o job atual.`);
}catch(error){ado.failed(error);}}
if(require.main===module)main();
module.exports={main};
