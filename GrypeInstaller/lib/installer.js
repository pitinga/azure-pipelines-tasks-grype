'use strict';
const https=require('node:https');
const fs=require('node:fs');
const fsp=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const {execute}=require('./cli');
const MAX_REDIRECTS=8;
const MAX_ASSET=512*1024*1024;
const MAX_METADATA=5*1024*1024;
function releaseName(version){const val=String(version||'').trim();if(val==='latest')return 'latest';const clean=val.replace(/^v/i,'');if(!/^\d+\.\d+\.\d+$/.test(clean))throw new Error('Versão deve ser latest ou X.Y.Z (estável).');return 'tags/v'+clean;}
function platformAsset(tool,version,platform=process.platform,arch=process.arch){if(!['grype','syft'].includes(tool))throw new Error('Ferramenta não suportada: '+tool);const osName={linux:'linux',darwin:'darwin',win32:'windows'}[platform];const cpu={x64:'amd64',arm64:'arm64'}[arch];if(!osName||!cpu)throw new Error(`SO/arquitetura não suportados: ${platform}/${arch}`);return `${tool}_${String(version).replace(/^v/,'')}_${osName}_${cpu}.${platform==='win32'?'zip':'tar.gz'}`;}
function authorized(uri){const u=new URL(uri);const host=u.hostname.toLowerCase();if(u.protocol!=='https:'||u.username||u.password||u.port||!(host==='github.com'||host==='api.github.com'||host==='githubusercontent.com'||host.endsWith('.githubusercontent.com')))throw new Error('Download redirecionado para host não autorizado: '+host);return u;}
async function request(url,destination=null,maxBytes=MAX_METADATA,redirects=0){if(redirects>MAX_REDIRECTS)throw new Error('Redirecionamentos excessivos do GitHub.');const u=authorized(url);const headers={'User-Agent':'pitinga-azure-pipelines-tasks-grype/0.1.0','Accept':'application/vnd.github+json'};if(u.hostname==='api.github.com'&&process.env.GITHUB_TOKEN)headers.Authorization=`Bearer ${process.env.GITHUB_TOKEN}`;
 const res=await new Promise((resolve,reject)=>{const req=https.get(u,{headers,timeout:120000},resolve);req.on('timeout',()=>req.destroy(new Error('Timeout ao baixar do GitHub.')));req.once('error',reject);});
 if([301,302,303,307,308].includes(res.statusCode)){const location=res.headers.location;res.resume();if(!location)throw new Error('Redirect sem Location.');return request(new URL(location,u).href,destination,maxBytes,redirects+1);}
 if(res.statusCode!==200){res.resume();throw new Error(`GitHub retornou HTTP ${res.statusCode} para ${u.hostname}.`);}
 let bytes=0;
 if(!destination){const chunks=[];for await(const chunk of res){bytes+=chunk.length;if(bytes>maxBytes)throw new Error('Metadados muito grandes.');chunks.push(chunk);}return Buffer.concat(chunks);}
 const output=fs.createWriteStream(destination,{flags:'wx'});
 try{for await(const chunk of res){bytes+=chunk.length;if(bytes>maxBytes)throw new Error('Asset excedeu limite de tamanho.');if(!output.write(chunk))await new Promise((resolve,reject)=>{output.once('drain',resolve);output.once('error',reject);});}await new Promise((resolve,reject)=>output.end(e=>e?reject(e):resolve()));return destination;}
 catch(e){output.destroy();throw e;}
}
async function getText(url){return (await request(url)).toString('utf8');}
function parseChecksum(body,filename){for(const line of body.split(/\r?\n/)){const m=line.match(/^([A-Fa-f0-9]{64})\s+\*?(.+)$/);if(m&&m[2].trim()===filename)return m[1].toLowerCase();}throw new Error('SHA-256 não encontrado para '+filename);}
async function sha256(file){const h=crypto.createHash('sha256');for await(const chunk of fs.createReadStream(file))h.update(chunk);return h.digest('hex');}
async function extract(archive,destination,tool,platform=process.platform){await fsp.mkdir(destination,{recursive:true});const executable=tool+(platform==='win32'?'.exe':'');if(platform==='win32'){
 const ps=`Expand-Archive -LiteralPath '${archive.replace(/'/g,"''")}' -DestinationPath '${destination.replace(/'/g,"''")}' -Force`;
 const encoded=Buffer.from(ps,'utf16le').toString('base64');await execute('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',encoded]);
 }else await execute('tar',['-xzf',archive,'-C',destination,'--',executable]);
 const result=path.join(destination,executable);if(!fs.existsSync(result))throw new Error('Executável não encontrado no archive: '+executable);if(platform!=='win32')await fsp.chmod(result,0o755);return result;
}
async function resolveRelease(tool,version){const url=`https://api.github.com/repos/anchore/${tool}/releases/${releaseName(version)}`;const data=JSON.parse(await getText(url));const tag=data.tag_name||'';if(!/^v\d+\.\d+\.\d+$/.test(tag)||data.prerelease||data.draft)throw new Error(`Release ${tool} não estável ou inválida.`);return data;}
async function installTool(tool,version,cacheRoot,settings={}) {
 const platform=settings.platform||process.platform;const arch=settings.arch||process.arch;
 // Never implicitly download any arbitrary repository or remote installer script.
 const release=await (settings.resolveRelease||resolveRelease)(tool,version);
 if(!/^v\d+\.\d+\.\d+$/.test(release.tag_name||'')||release.prerelease||release.draft)throw new Error('Release rejeitada: não estável.');
 const actual=release.tag_name.slice(1),filename=platformAsset(tool,actual,platform,arch),checksumName=`${tool}_${actual}_checksums.txt`;
 const asset=release.assets?.find(a=>a.name===filename),checksum=release.assets?.find(a=>a.name===checksumName);
 if(!asset||!checksum)throw new Error(`Asset oficial não disponível para ${platform}/${arch}: ${filename} ou ${checksumName}.`);
 authorized(asset.browser_download_url);authorized(checksum.browser_download_url);
 const targetDir=path.join(cacheRoot,tool,actual,`${platform}-${arch}`),binary=path.join(targetDir,tool+(platform==='win32'?'.exe':'')),marker=path.join(targetDir,'.verified');
 if(fs.existsSync(binary)&&fs.existsSync(marker)){console.log(`Reutilizando ${tool} ${actual} do cache do agente.`);return {tool,version:actual,binary,cached:true};}
 const temporary=await fsp.mkdtemp(path.join(os.tmpdir(),`${tool}-install-`));
 try{
  const checksumText=await (settings.getText||getText)(checksum.browser_download_url),expected=parseChecksum(checksumText,filename);
  const archive=path.join(temporary,filename);await (settings.request||request)(asset.browser_download_url,archive,MAX_ASSET);
  const received=await sha256(archive);if(received!==expected)throw new Error('Verificação SHA-256 falhou para '+filename);
  console.log(`${tool} ${actual}: SHA-256 verificado (${platform}/${arch}).`);
  const stage=path.join(temporary,'stage');await (settings.extract||extract)(archive,stage,tool,platform);
  await fsp.writeFile(path.join(stage,'.verified'),`${received}  ${filename}\n`);
  await fsp.mkdir(path.dirname(targetDir),{recursive:true});
  if(fs.existsSync(targetDir))await fsp.rm(targetDir,{recursive:true,force:true});
  try{await fsp.rename(stage,targetDir);}catch(error){if(error.code!=='EXDEV')throw error;await fsp.cp(stage,targetDir,{recursive:true,force:true});}
  return {tool,version:actual,binary,cached:false};
 }finally{await fsp.rm(temporary,{recursive:true,force:true});}
}
module.exports={releaseName,platformAsset,authorized,parseChecksum,resolveRelease,installTool,sha256};
