'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const fs=require('node:fs'),fsp=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {installTool}=require('../lib/installer');
const root=path.resolve(__dirname,'..');
test('Installer simulado confere SHA-256 e reutiliza cache',async()=>{
 const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'grype-installer-test-'));
 const content=Buffer.from('verified mock archive');const hash=crypto.createHash('sha256').update(content).digest('hex');
 let downloads=0;const ver='0.122.1',file=`grype_${ver}_linux_amd64.tar.gz`;
 const release={tag_name:'v'+ver,prerelease:false,draft:false,assets:[{name:file,browser_download_url:'https://github.com/anchore/grype/releases/download/v'+ver+'/'+file},{name:`grype_${ver}_checksums.txt`,browser_download_url:'https://github.com/anchore/grype/releases/download/v'+ver+'/checksums'}]};
 const settings={platform:'linux',arch:'x64',resolveRelease:async()=>release,getText:async()=>`${hash}  ${file}\n`,request:async(_url,dest)=>{downloads++;await fsp.writeFile(dest,content);},extract:async(_archive,dest,tool)=>{await fsp.mkdir(dest,{recursive:true});const binary=path.join(dest,tool);await fsp.writeFile(binary,'mock');return binary;}};
 try{const a=await installTool('grype',ver,dir,settings);assert.equal(a.version,ver);assert.equal(a.cached,false);assert.equal(downloads,1);assert.ok(fs.existsSync(a.binary));
 const b=await installTool('grype',ver,dir,settings);assert.equal(b.cached,true);assert.equal(downloads,1);
 await fsp.rm(path.join(dir,'grype',ver,'linux-x64'),{recursive:true});
 await assert.rejects(()=>installTool('grype',ver,dir,{...settings,getText:async()=>`${'0'.repeat(64)}  ${file}\n`}),/SHA-256/);
 }finally{await fsp.rm(dir,{recursive:true,force:true});}
});
test('GrypeScan passa arrays sem shell e exporta GRYPE_DB_AUTO_UPDATE',async()=>{
 if(process.platform==='win32')return;
 const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'grype-run-test-'));
 try{
  const script=path.join(dir,'grype'),capture=path.join(dir,'args.json');
  await fsp.writeFile(script,`#!/usr/bin/env node\nrequire('node:fs').writeFileSync(process.env.CAPTURE_FILE,JSON.stringify({args:process.argv.slice(2),env:process.env.GRYPE_DB_AUTO_UPDATE}));\n`);await fsp.chmod(script,0o755);
  const out=spawnSync(process.execPath,[path.join(root,'GrypeScan/index.js')],{encoding:'utf8',cwd:dir,env:{...process.env,GRYPE_PATH:script,CAPTURE_FILE:capture,INPUT_WORKINGDIRECTORY:dir,INPUT_TARGET:'image:test; echo SECRET',INPUT_SOURCETYPE:'registry',INPUT_FORMAT:'json',INPUT_FAILON:'critical',INPUT_DBAUTOUPDATE:'false'}});
  assert.equal(out.status,0,out.stdout+out.stderr);assert.match(out.stdout,/result=Succeeded/);
  const data=JSON.parse(await fsp.readFile(capture,'utf8'));
  assert.deepEqual(data.args,['--output','json','--fail-on','critical','--','registry:image:test; echo SECRET']);assert.equal(data.env,'false');
 }finally{await fsp.rm(dir,{recursive:true,force:true});}
});
test('GrypeScan mantém código de saída 2 e marca failure no Azure',async()=>{
 if(process.platform==='win32')return;
 const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'grype-fail-test-'));
 try{
  const script=path.join(dir,'grype');await fsp.writeFile(script,'#!/usr/bin/env node\nprocess.exit(2);\n');await fsp.chmod(script,0o755);
  const run=spawnSync(process.execPath,[path.join(root,'GrypeScan/index.js')],{encoding:'utf8',cwd:dir,env:{...process.env,GRYPE_PATH:script,INPUT_TARGET:'dir:.',INPUT_WORKINGDIRECTORY:dir,INPUT_FAILON:'high'}});
  assert.equal(run.status,1);assert.match(run.stdout,/terminou com código 2/);assert.match(run.stdout,/result=Failed/);
 }finally{await fsp.rm(dir,{recursive:true,force:true});}
});
test('Syft opcional gera SBOM, passa sbom: ao Grype e preserva arquivo solicitado',async()=>{
 if(process.platform==='win32')return;
 const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'grype-syft-e2e-'));
 try{
  const syft=path.join(dir,'syft'),grype=path.join(dir,'grype'),report=path.join(dir,'grype-argv.json'),sbom=path.join(dir,'results','bom.json');
  await fsp.writeFile(syft,`#!/usr/bin/env node\nconst fs=require('node:fs'),p=require('node:path');const out=process.argv.find(x=>x.startsWith('syft-json='))?.slice(10);if(!out)process.exit(17);fs.mkdirSync(p.dirname(out),{recursive:true});fs.writeFileSync(out,'{"artifacts":[]}');\n`);
  await fsp.writeFile(grype,`#!/usr/bin/env node\nrequire('node:fs').writeFileSync(process.env.CAPTURE_FILE,JSON.stringify(process.argv.slice(2)));\n`);await fsp.chmod(syft,0o755);await fsp.chmod(grype,0o755);
  const run=spawnSync(process.execPath,[path.join(root,'GrypeScan/index.js')],{encoding:'utf8',cwd:dir,env:{...process.env,GRYPE_PATH:grype,SYFT_PATH:syft,CAPTURE_FILE:report,INPUT_TARGET:'.',INPUT_SOURCETYPE:'dir',INPUT_GENERATESBOM:'true',INPUT_SBOMFILE:sbom,INPUT_WORKINGDIRECTORY:dir}});
  assert.equal(run.status,0,run.stdout+run.stderr);
  const args=JSON.parse(await fsp.readFile(report,'utf8'));assert.deepEqual(args.slice(-2),['--','sbom:'+sbom]);assert.ok(fs.existsSync(sbom));
 }finally{await fsp.rm(dir,{recursive:true,force:true});}
});
