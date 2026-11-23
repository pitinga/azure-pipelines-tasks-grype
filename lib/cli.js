'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {spawn}=require('node:child_process');
function parseArguments(line) {
  const result=[];let token='',quote=null,started=false;
  for(let i=0;i<line.length;i++) {
    const c=line[i];
    if(!quote && /\s/.test(c)){if(started){result.push(token);token='';started=false;}continue;}
    if(c==='"'||c==="'") {if(quote===c){quote=null;continue;} if(!quote){quote=c;started=true;continue;}}
    if(c==='\\' && quote!=="'" && i+1<line.length && (line[i+1]==='"'||(!quote&&/\s/.test(line[i+1])))) {token+=line[++i];started=true;continue;}
    token+=c;started=true;
  }
  if(quote)throw new Error('Aspas não fechadas em additionalArguments.');
  if(started)result.push(token);
  return result;
}
function onPath(binary,env=process.env,platform=process.platform){const names=platform==='win32'?[binary+'.exe',binary]:[binary];for(const dir of (env.PATH||env.Path||'').split(path.delimiter)){if(!dir)continue;for(const name of names){const candidate=path.join(dir,name);if(fs.existsSync(candidate)&&fs.statSync(candidate).isFile())return candidate;}}return null;}
function locate(binary,env=process.env){const key=binary.toUpperCase()+'_PATH';const explicit=env[key];if(explicit){if(!fs.existsSync(explicit))throw new Error(`${key} não existe: ${explicit}`);return explicit;}const found=onPath(binary,env);if(found)return found;throw new Error(`${binary} não encontrado. Execute GrypeInstaller@0 antes, no mesmo job.`);}
function execute(cmd,args,options={}){return new Promise((resolve,reject)=>{const child=spawn(cmd,args,{...options,shell:false,stdio:options.stdio||'inherit'});child.once('error',reject);child.once('close',(code,signal)=>code===0?resolve():reject(new Error(`${path.basename(cmd)} terminou com código ${code??'desconhecido'}${signal?' (sinal '+signal+')':''}.`)));});}
module.exports={parseArguments,onPath,locate,execute};
