'use strict';
const fs=require('node:fs');const path=require('node:path');const {execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),dir=path.join(root,'dist');const packages=fs.readdirSync(dir).filter(f=>f.endsWith('.vsix'));
if(packages.length!==1)throw new Error('Esperado exatamente um VSIX.');
const vsix=path.join(dir,packages[0]);const xml=execFileSync('unzip',['-p',vsix,'extension.vsixmanifest'],{encoding:'utf8'});
const items=[['Microsoft.VisualStudio.Services.Icons.Default','images/extension-icon.png'],['Microsoft.VisualStudio.Services.Content.Details','overview.md'],['Microsoft.VisualStudio.Services.Content.License','LICENSE']];
for(const [type,file]of items){const tag=xml.match(new RegExp('<Asset\\b[^>]*\\bType="'+type.replace(/\./g,'\\.')+'"[^>]*>'));if(!tag||!tag[0].includes('Path="'+file+'"'))throw new Error('Asset não registrado: '+type+' -> '+file);const bytes=execFileSync('unzip',['-p',vsix,file]);if(bytes.length<100)throw new Error('Asset vazio: '+file);if(file.endsWith('.png')&&(bytes.readUInt32BE(16)!==128||bytes.readUInt32BE(20)!==128))throw new Error('Ícone deve ter 128x128.');}
const m=require('../vss-extension.json');if(!xml.includes('Version="'+m.version+'"'))throw new Error('Manifesto VSIX com versão divergente.');
for(const task of ['GrypeInstaller','GrypeScan']){const info=JSON.parse(execFileSync('unzip',['-p',vsix,task+'/task.json'],{encoding:'utf8'}));if(JSON.stringify(Object.keys(info.execution))!=='["Node24"]'||info.minimumAgentVersion!=='4.265.1')throw new Error('Task não compatível com Node24: '+task);}
console.log('VSIX validado: '+packages[0]);
