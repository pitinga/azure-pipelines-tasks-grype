'use strict';
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const ado=require('./lib/ado');
const {locate,execute,parseArguments}=require('./lib/cli');
const FORMATS=new Set(['table','json','cyclonedx','cyclonedx-json','sarif','template']);
const SOURCES=new Set(['auto','docker','registry','podman','containerd','docker-archive','oci-archive','oci-dir','singularity','dir','file','sbom']);
const SEVERITIES=new Set(['none','negligible','low','medium','high','critical']);
const STATES=new Set(['fixed','not-fixed','unknown','wont-fix']);
const SCOPES=new Set(['squashed','all-layers','deep-squashed']);
const SORTS=new Set(['package','severity','epss','risk','kev','vulnerability']);
const DB_OPERATIONS={dbCheck:'check',dbUpdate:'update',dbStatus:'status',dbList:'list',dbProviders:'providers',dbDelete:'delete',dbImport:'import',dbDiff:'diff',dbSearch:'search'};
function lines(value){return String(value||'').split(/[;\r\n]+/).map(x=>x.trim()).filter(Boolean);}
function isSourcePrefix(target){return /^(?:dir|file|sbom|docker|registry|podman|containerd|docker-archive|oci-archive|oci-dir|singularity|purl|cpes|zarf):/.test(target);}
function val(read,name,allowed,fallback){const value=read(name,fallback);if(!allowed.has(value))throw new Error(`${name} inválido: ${value}. Valores: ${[...allowed].join(', ')}`);return value;}
function boolFlag(boolean,name,args,flag){if(boolean(name))args.push(flag);}
function repeat(read,name,args,option){for(const value of lines(read(name)))args.push(option,value);}
function buildArgs(read=ado.input,boolean=ado.flag){
 const operation=read('operation','scan');const args=[];
 if(operation!=='scan'){
  if(!DB_OPERATIONS[operation])throw new Error('Operação não suportada: '+operation);
  args.push('db',DB_OPERATIONS[operation]);
  if(['dbImport','dbDiff'].includes(operation)){
   const target=read('target');if(!target)throw new Error(operation+' requer target (arquivo, URL ou referência de banco).');args.push(target);
  }
  args.push(...parseArguments(read('additionalArguments')));
  return {args,outputFile:'',source:'',operation,env:{}};
 }
 const target=read('target');if(!target)throw new Error('target é obrigatório para scan do Grype.');
 const sourceType=val(read,'sourceType',SOURCES,'auto');
 if(sourceType!=='auto'&&isSourcePrefix(target))throw new Error('Alvo já contém prefixo de origem; use sourceType=auto.');
 if(sourceType!=='auto'&&read('fromSources'))throw new Error('Use sourceType ou fromSources, não ambos.');
 const source=sourceType==='auto'?target:`${sourceType}:${target}`;
 const format=val(read,'format',FORMATS,'table');const otherFormats=lines(read('additionalFormats'));
 for(const f of otherFormats)if(!FORMATS.has(f))throw new Error('Formato adicional inválido: '+f);
 args.push('--output',format);for(const f of otherFormats)args.push('--output',f);
 const failOn=val(read,'failOn',SEVERITIES,'none');if(failOn!=='none')args.push('--fail-on',failOn);
 const scope=val(read,'scope',SCOPES,'squashed');if(scope!=='squashed')args.push('--scope',scope);
 const sortBy=val(read,'sortBy',SORTS,'risk');if(sortBy!=='risk')args.push('--sort-by',sortBy);
 const flags=[['distro','--distro'],['platform','--platform'],['name','--name'],['template','--template'],['ignoreStates','--ignore-states']];
 for(const [key,flag]of flags){const v=read(key);if(v)args.push(flag,v);}
 const states=read('ignoreStates');if(states){const all=states.split(',').map(x=>x.trim());if(all.some(x=>!STATES.has(x)))throw new Error('ignoreStates aceita: fixed,not-fixed,unknown,wont-fix.');}
 repeat(read,'fromSources',args,'--from');repeat(read,'excludePaths',args,'--exclude');repeat(read,'configFiles',args,'--config');repeat(read,'profiles',args,'--profile');repeat(read,'vexFiles',args,'--vex');
 boolFlag(boolean,'byCve',args,'--by-cve');boolFlag(boolean,'onlyFixed',args,'--only-fixed');boolFlag(boolean,'onlyNotFixed',args,'--only-notfixed');
 boolFlag(boolean,'addCpesIfNone',args,'--add-cpes-if-none');boolFlag(boolean,'showSuppressed',args,'--show-suppressed');boolFlag(boolean,'quiet',args,'--quiet');
 const verbosity=read('verbose','0');if(!['0','1','2'].includes(verbosity))throw new Error('verbose aceita 0, 1 ou 2.');if(verbosity==='1')args.push('-v');if(verbosity==='2')args.push('-vv');
 if(boolean('onlyFixed')&&boolean('onlyNotFixed'))throw new Error('onlyFixed e onlyNotFixed são mutuamente exclusivos.');
 if(boolean('showSuppressed')&&(format!=='table'||otherFormats.length))throw new Error('showSuppressed exige saída exclusivamente table.');
 if(read('template')&&format!=='template'&&!otherFormats.includes('template'))throw new Error('template exige formato template.');
 if(format==='template'&&!read('template'))throw new Error('Formato template requer template (arquivo Go template).');
 if(boolean('quiet')&&verbosity!=='0')throw new Error('quiet e verbose não podem ser combinados.');
 const outputFile=read('outputFile');if(outputFile)args.push('--file',outputFile);
 args.push(...parseArguments(read('additionalArguments')));
 // End option parsing before an arbitrary user target: no shell, no expansion.
 args.push('--',source);
 const env={};const dbCacheDir=read('dbCacheDir');if(dbCacheDir)env.GRYPE_DB_CACHE_DIR=dbCacheDir;
 if(!boolean('dbAutoUpdate',true))env.GRYPE_DB_AUTO_UPDATE='false';
 return {args,outputFile,source,operation,env};
}
async function main(){try{
 const cwd=ado.validDirectory(ado.input('workingDirectory',process.env.SYSTEM_DEFAULTWORKINGDIRECTORY||process.cwd()));
 const plan=buildArgs();const grype=locate('grype');const env={...process.env,...plan.env};
 if(plan.outputFile)fs.mkdirSync(path.dirname(path.resolve(cwd,plan.outputFile)),{recursive:true});
 let sbomPath=null,removeSbom=false;
 try{
  if(plan.operation==='scan'&&ado.flag('generateSbom')){
   if(plan.source.startsWith('sbom:'))throw new Error('generateSbom não deve ser usado para um alvo já SBOM.');
   const syft=locate('syft');const requested=ado.input('sbomFile');
   sbomPath=requested?path.resolve(cwd,requested):path.join(process.env.AGENT_TEMPDIRECTORY||os.tmpdir(),`grype-syft-${crypto.randomUUID()}.json`);
   removeSbom=!requested;fs.mkdirSync(path.dirname(sbomPath),{recursive:true});
   console.log('Gerando SBOM Syft JSON antes de analisar com Grype.');
   await execute(syft,[plan.source,'-o',`syft-json=${sbomPath}`],{cwd,env});
   if(!fs.existsSync(sbomPath)||fs.statSync(sbomPath).size===0)throw new Error('Syft não produziu SBOM válida.');
   plan.args[plan.args.length-1]='sbom:'+sbomPath;
  }
  console.log(`Grype ${plan.operation}: executando ${path.basename(grype)} sem shell.`);
  await execute(grype,plan.args,{cwd,env});
  ado.complete('Grype concluído.');
 }finally{if(sbomPath&&removeSbom&&fs.existsSync(sbomPath))fs.rmSync(sbomPath,{force:true});}
}catch(error){ado.failed(error);}}
if(require.main===module)main();
module.exports={buildArgs,main,lines,isSourcePrefix};
