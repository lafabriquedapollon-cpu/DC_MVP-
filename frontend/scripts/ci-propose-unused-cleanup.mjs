// Generate a REVIEW-ONLY patch using the pinned TypeScript language service.
// Never publish or commit its changes automatically. The CI checkout is disposable.
import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
assert.equal(process.env.GITHUB_ACTIONS,'true');
assert.equal(process.env.DC_UNUSED_PROPOSAL,'yes');
const root=process.cwd();
assert(fs.existsSync(path.join(root,'tsconfig.app.json')));
const config=ts.readConfigFile('tsconfig.app.json',ts.sys.readFile);
assert(!config.error);
const parsed=ts.parseJsonConfigFileContent(config.config,ts.sys,root);
assert.equal(parsed.errors.length,0);
const versions=new Map();
const host={...ts.sys,useCaseSensitiveFileNames:()=>ts.sys.useCaseSensitiveFileNames,getNewLine:()=>ts.sys.newLine,getScriptFileNames:()=>parsed.fileNames,getScriptVersion:f=>String(versions.get(f)||0),getScriptSnapshot:f=>{const s=ts.sys.readFile(f);return s===undefined?undefined:ts.ScriptSnapshot.fromString(s)},getCurrentDirectory:()=>root,getCompilationSettings:()=>parsed.options,getDefaultLibFileName:o=>ts.getDefaultLibFilePath(o)};
const service=ts.createLanguageService(host);
const isUnused=d=>[6133,6196,6192].includes(d.code);
for(let pass=1;pass<=5;pass++){
  let count=0;
  for(const file of parsed.fileNames){
    if(!file.startsWith(path.join(root,'src')+path.sep))continue;
    const diag=service.getSemanticDiagnostics(file).filter(isUnused);
    if(!diag.length)continue;
    // A single diagnostic may not advertise a fixId; the combined deletion fix still applies.
    const result=service.getCombinedCodeFix({type:'file',fileName:file},'unusedIdentifier_delete',{},{});
    for(const change of result.changes){
      assert.equal(path.resolve(change.fileName),path.resolve(file),'cross-file fix refused');
      let body=fs.readFileSync(file,'utf8');
      for(const edit of [...change.textChanges].sort((a,b)=>b.span.start-a.span.start))body=body.slice(0,edit.span.start)+edit.newText+body.slice(edit.span.start+edit.span.length);
      fs.writeFileSync(file,body);versions.set(file,(versions.get(file)||0)+1);count++;
    }
  }
  console.log('UNUSED_PROPOSAL_PASS',pass,'filesChanged',count);
  if(!count)break;
}
service.dispose();
