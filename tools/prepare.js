'use strict';
const fs=require('node:fs');const path=require('node:path');const root=path.resolve(__dirname,'..');
for(const task of ['GrypeInstaller','GrypeScan']){
 const destination=path.join(root,task,'lib');fs.mkdirSync(destination,{recursive:true});
 for(const name of task==='GrypeInstaller'?['ado.js','cli.js','installer.js']:['ado.js','cli.js'])fs.copyFileSync(path.join(root,'lib',name),path.join(destination,name));
}
console.log('Bibliotecas independentes copiadas para ambas as tasks Node24.');
