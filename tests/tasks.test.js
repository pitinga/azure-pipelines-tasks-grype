'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const fs=require('node:fs');const path=require('node:path');
const {buildArgs}=require('../GrypeScan/index');
const {parseArguments}=require('../lib/cli');
const {releaseName,platformAsset,parseChecksum,authorized}=require('../lib/installer');
const root=path.resolve(__dirname,'..');
const config=(values={})=>[(name,fallback='')=>values[name]??fallback,(name,fallback=false)=>values[name]??fallback];
test('Manifest: duas tasks Node24 independentes, privadas e originais',()=>{
 const manifest=require('../vss-extension.json'),installer=require('../GrypeInstaller/task.json'),scanner=require('../GrypeScan/task.json');
 assert.equal(manifest.version,'0.1.3');assert.equal(manifest.public,true);assert.equal(manifest.id,'azure-pipelines-tasks-grype');assert.equal(manifest.publisher,'pitinga');
 assert.deepEqual(manifest.contributions.map(x=>x.properties.name),['GrypeInstaller','GrypeScan']);
 for(const t of [installer,scanner]){assert.deepEqual(Object.keys(t.execution),['Node24']);assert.equal(t.minimumAgentVersion,'4.265.1');assert.equal(t.version.Major,0);}
 assert.notEqual(installer.id,scanner.id);
 assert.equal(installer.inputs.length,2);assert.equal(installer.inputs[0].defaultValue,'latest');assert.equal(installer.inputs[1].defaultValue,'latest');
 const names=scanner.inputs.map(x=>x.name);
 for(const field of ['sourceType','target','failOn','onlyFixed','ignoreStates','format','outputFile','byCve','generateSbom','dbCacheDir','dbAutoUpdate','additionalArguments'])assert.ok(names.includes(field),field);
 assert.equal(require('../package.json').engines.node,'>=24');
});
test('Release: latest e versões estáveis; releases suspeitas rejeitadas',()=>{
 assert.equal(releaseName('latest'),'latest');assert.equal(releaseName('0.122.1'),'tags/v0.122.1');assert.equal(releaseName('v1.57.2'),'tags/v1.57.2');
 for(const input of ['v1.2.3-beta','1.2','../latest','latest;rm -rf /','v1.1.1/foo',''])assert.throws(()=>releaseName(input));
});
test('Assets: Linux, macOS e Windows em AMD64 e ARM64',()=>{
 for(const [tool,v] of [['grype','0.122.1'],['syft','1.57.2']]){
  assert.equal(platformAsset(tool,v,'linux','x64'),`${tool}_${v}_linux_amd64.tar.gz`);
  assert.equal(platformAsset(tool,v,'linux','arm64'),`${tool}_${v}_linux_arm64.tar.gz`);
  assert.equal(platformAsset(tool,v,'darwin','arm64'),`${tool}_${v}_darwin_arm64.tar.gz`);
  assert.equal(platformAsset(tool,v,'win32','x64'),`${tool}_${v}_windows_amd64.zip`);
  assert.equal(platformAsset(tool,v,'win32','arm64'),`${tool}_${v}_windows_arm64.zip`);
 }
 assert.throws(()=>platformAsset('grype','0.122.1','freebsd','x64'));
 assert.throws(()=>platformAsset('wrong','1.0.0','linux','x64'));
});
test('URLs HTTPS estritas; checksum exige nome exato',()=>{
 for(const url of ['http://github.com/','https://github.com.evil.example/','https://evil.example','https://a.githubusercontent.com.evil.example/file','https://user:secret@github.com/x','https://github.com:8080/x'])assert.throws(()=>authorized(url));
 assert.equal(authorized('https://release-assets.githubusercontent.com/a').hostname,'release-assets.githubusercontent.com');
 assert.equal(authorized('https://api.github.com/repos/anchore/grype').hostname,'api.github.com');
 const hash='a'.repeat(64);assert.equal(parseChecksum(`${hash}  grype_0.122.1_linux_amd64.tar.gz\n`,'grype_0.122.1_linux_amd64.tar.gz'),hash);
 assert.throws(()=>parseChecksum(`${hash}  grype_0.122.1_linux_arm64.tar.gz\n`,'grype_0.122.1_linux_amd64.tar.gz'));
});
test('Scan mínimo preserva origem e não usa shell',()=>{
 assert.deepEqual(buildArgs(...config({target:'dir:.'})).args,['--output','table','--','dir:.']);
 assert.deepEqual(buildArgs(...config({target:'file:/tmp/app.jar',sourceType:'auto'})).args,['--output','table','--','file:/tmp/app.jar']);
 assert.deepEqual(buildArgs(...config({target:'myregistry/app:v2;echo SECRET',sourceType:'registry',format:'json',failOn:'high'})).args,['--output','json','--fail-on','high','--','registry:myregistry/app:v2;echo SECRET']);
});
test('Todas as flags primárias do Grype geradas corretamente',()=>{
 const vals={target:'alpine:3.20',sourceType:'docker',format:'sarif',outputFile:'reports/scan.sarif',failOn:'medium',byCve:true,onlyFixed:true,addCpesIfNone:true,excludePaths:'**/node_modules/**\n**/.git/**',scope:'all-layers',sortBy:'severity',platform:'linux/amd64',distro:'alpine:3.20',name:'Scan ACR',configFiles:'config a.yaml\nconfig b.yaml',profiles:'ci\nprod',vexFiles:'vex1.json\nvex 2.json',dbAutoUpdate:false,dbCacheDir:'/tmp/grype-db',additionalArguments:'--verbose'};
 const p=buildArgs(...config(vals));const args=p.args.join('\u001f');
 for(const value of ['--output\u001fsarif','--file\u001freports/scan.sarif','--fail-on\u001fmedium','--by-cve','--only-fixed','--add-cpes-if-none','--scope\u001fall-layers','--sort-by\u001fseverity','--platform\u001flinux/amd64','--distro\u001falpine:3.20','--name\u001fScan ACR','--exclude\u001f**/node_modules/**','--exclude\u001f**/.git/**','--config\u001fconfig a.yaml','--config\u001fconfig b.yaml','--profile\u001fci','--profile\u001fprod','--vex\u001fvex 2.json','--verbose'])assert.ok(args.includes(value),value);
 assert.deepEqual(p.env,{GRYPE_DB_CACHE_DIR:'/tmp/grype-db',GRYPE_DB_AUTO_UPDATE:'false'});
 assert.deepEqual(p.args.slice(-2),['--','docker:alpine:3.20']);
});
test('--from explícito é passado nativamente e bloqueia conflitos',()=>{
 const p=buildArgs(...config({target:'alpine:latest',fromSources:'docker\nregistry'}));
 assert.deepEqual(p.args,['--output','table','--from','docker','--from','registry','--','alpine:latest']);
 assert.throws(()=>buildArgs(...config({target:'alpine:latest',sourceType:'registry',fromSources:'docker'})));
});
test('Vulnerabilidades sem correção e grupos de resultados',()=>{
 const p=buildArgs(...config({target:'dir:.',ignoreStates:'not-fixed,unknown,wont-fix',additionalFormats:'json'}));
 assert.ok(p.args.includes('--ignore-states'));assert.equal(p.args.filter(x=>x==='--output').length,2);
 assert.deepEqual(buildArgs(...config({target:'dir:.',onlyNotFixed:true})).args.slice(0,3),['--output','table','--only-notfixed']);
});
test('Validações de entrada: fail-on e formatos, somente fixed e template',()=>{
 for(const input of [
  {target:'.',failOn:'CRITICAL'}, {target:'.',format:'spdx-json'}, {target:'.',sourceType:'k8s'},
  {target:'.',scope:'full'}, {target:'.',sortBy:'random'}, {target:'.',ignoreStates:'bad-state'},
  {target:'.',onlyFixed:true,onlyNotFixed:true},{target:'.',showSuppressed:true,format:'json'},
  {target:'.',format:'template'}, {target:'.',template:'custom.tpl'},
  {target:'.',verbose:'4'},{target:'.',quiet:true,verbose:'2'},
  {target:'dir:.',sourceType:'dir'}, {target:''},
 ])assert.throws(()=>buildArgs(...config(input)),JSON.stringify(input));
});
test('DB operations nativas não recebem flags de scan',()=>{
 assert.deepEqual(buildArgs(...config({operation:'dbUpdate'})).args,['db','update']);
 assert.deepEqual(buildArgs(...config({operation:'dbStatus',additionalArguments:'--output json'})).args,['db','status','--output','json']);
 assert.deepEqual(buildArgs(...config({operation:'dbImport',target:'db.tar.zst'})).args,['db','import','db.tar.zst']);
 assert.deepEqual(buildArgs(...config({operation:'dbDelete'})).args,['db','delete']);
 assert.throws(()=>buildArgs(...config({operation:'dbImport'})));
});
test('Argumentos extras com aspas não são interpretados por shell',()=>{
 assert.deepEqual(parseArguments('--config "C:\\My Folder\\grype.yaml" --profile release'),['--config','C:\\My Folder\\grype.yaml','--profile','release']);
 assert.deepEqual(parseArguments('--foo "two words" --other'),['--foo','two words','--other']);
 assert.throws(()=>parseArguments('--foo "unfinished'));
});
test('Pipeline matrix Node24, Github Actions moderno, sem Node20',()=>{
 const ci=fs.readFileSync(path.join(root,'.github/workflows/validate-and-package.yml'),'utf8');
 for(const expected of ['actions/checkout@v7','actions/setup-node@v7','actions/upload-artifact@v7',"node-version: '24'",'windows-latest','macos-latest','ubuntu-latest'])assert.ok(ci.includes(expected));
 assert.ok(!ci.includes('Node20'));
});

test('Smoke test manual usa Node24 e downloads reais por matriz sem publicar',()=>{
 const workflow=fs.readFileSync(path.join(root,'.github/workflows/smoke-real-downloads.yml'),'utf8');
 assert.match(workflow,/workflow_dispatch:/);
 assert.match(workflow,/ubuntu-latest, windows-latest, macos-latest/);
 assert.match(workflow,/node-version: '24'/);
 assert.match(workflow,/node tools\/smoke-real.js/);
 assert.doesNotMatch(workflow,/extension publish|marketplace-production/);
});


test('MIT license included in VSIX with explicit asset and byte-level verification',()=>{
 const m=require('../vss-extension.json');
 assert.equal(m.version,'0.1.3');
 assert.equal(require('../package.json').version,m.version);
 assert.equal(m.content.license.path,'LICENSE');
 assert.ok(m.files.some(f=>f.path==='LICENSE'&&f.addressable===true));
 assert.match(fs.readFileSync(path.join(root,'LICENSE'),'utf8'),/MIT License/);
 assert.match(fs.readFileSync(path.join(root,'tools/verify-vsix.js'),'utf8'),/bytes.equals\(fs.readFileSync/);
});


test('Public 0.x.y release preserves 0.1 and task Major @0',()=>{
 const m=require('../vss-extension.json');
 assert.match(m.version,/^0\.1\.\d+$/);
 assert.equal(m.public,true);
 assert.equal(require('../package.json').version,m.version);
 for(const c of m.contributions.filter(x=>x.type==='ms.vss-distributed-task.task')){
  const task=require('../'+c.properties.name+'/task.json');
  assert.equal(task.version.Major,0);
 }
});


test('Marketplace public identity and product title',()=>{
 const manifest=require('../vss-extension.json');
 assert.equal(manifest.publisher,'pitinga');
 assert.equal(manifest.id,'azure-pipelines-tasks-grype');
 assert.equal(manifest.name,'Grype - Installer & Scanner');
 assert.equal(manifest.version,'0.1.3');
 assert.equal(manifest.public,true);
});

test('CI-approved GitHub Release is independent of Marketplace and never mutates published assets',()=>{
 const workflow=fs.readFileSync(path.join(root,'.github/workflows/github-release.yml'),'utf8');
 const release=fs.readFileSync(path.join(root,'.github/scripts/github-release.sh'),'utf8');
 const marketplace=fs.readFileSync(path.join(root,'.github/workflows/publish-public.yml'),'utf8');
 assert.match(workflow,/workflow_run:/);
 assert.match(workflow,/conclusion == 'success'/);
 assert.match(workflow,/contents: write/);
 assert.match(release,/gh run download/);
 assert.match(release,/gh release create/);
 assert.match(release,/never move existing tags/);
 assert.match(release,/LICENSE/);
 assert.doesNotMatch(release,/extension publish|VS_MARKETPLACE_TOKEN/);
 assert.doesNotMatch(marketplace,/gh release (create|upload|edit)/);
 assert.doesNotMatch(marketplace,/^\s+push:/m);
 assert.match(marketplace,/workflow_dispatch:/);
});
