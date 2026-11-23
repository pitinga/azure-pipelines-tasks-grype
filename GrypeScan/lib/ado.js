'use strict';
const fs = require('node:fs');
const path = require('node:path');
function input(name, fallback = '') {
  const key = 'INPUT_' + name.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  const value = process.env[key];
  return value === undefined || value === '' ? fallback : value.trim();
}
function flag(name, fallback = false) {
  const value = input(name, String(fallback)).toLowerCase();
  if (!['true', 'false'].includes(value)) throw new Error(`Entrada ${name}: use true ou false.`);
  return value === 'true';
}
function escapeVso(value) { return String(value).replace(/%/g,'%AZP25').replace(/\r/g,'%0D').replace(/\n/g,'%0A').replace(/;/g,'%3B').replace(/\]/g,'%5D'); }
function setVariable(name, value) { console.log(`##vso[task.setvariable variable=${name};]${escapeVso(value)}`); }
function prependPath(folder) { console.log(`##vso[task.prependpath]${escapeVso(folder)}`); }
function complete(msg) { console.log(`##vso[task.complete result=Succeeded;]${escapeVso(msg)}`); }
function failed(error) { const msg=error instanceof Error?error.message:String(error);console.log(`##vso[task.logissue type=error;]${escapeVso(msg)}`);console.log(`##vso[task.complete result=Failed;]${escapeVso(msg)}`);process.exitCode=1; }
function validDirectory(folder) {const full=path.resolve(folder||process.cwd());if(!fs.existsSync(full)||!fs.statSync(full).isDirectory())throw new Error(`Diretório não encontrado: ${full}`);return full;}
module.exports={input,flag,escapeVso,setVariable,prependPath,complete,failed,validDirectory};
