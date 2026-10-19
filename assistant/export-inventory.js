import {writeFile,readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {capabilityCatalog,capabilityDefinitions} from '../mcp/index.js';
import {registry} from '../mcp/registry.js';
import {automationTestHooks} from '../automations.js';
import {modelCatalog} from './models.js';
import {productGuides} from './guides.js';

export function fieldInventory(schema,prefix='',mode='input'){
 const fields=[];
 for(const [key,value]of Object.entries(schema.properties||{})){
  const path=prefix?prefix+'.'+key:key;
  fields.push({id:path,access:mode==='input'?'argument':'read',required:(schema.required||[]).includes(key),schema:value});
  fields.push(...fieldInventory(value,path,mode));
  if(value.items)fields.push(...fieldInventory(value.items,path+'.*',mode));
 }
 for(const branch of schema.anyOf||schema.oneOf||[])fields.push(...fieldInventory(branch,prefix,mode));
 return fields;
}
export function inventory(){
 const capabilities=capabilityCatalog(capabilityDefinitions({app:{locals:{quoteCalculator:{}}}})).map(d=>({...d,fields:[...fieldInventory(d.input_schema).map(f=>({...f,id:d.id+'.input.'+f.id})),...fieldInventory(d.output_schema,'','output').map(f=>({...f,id:d.id+'.output.'+f.id}))]}));
 const records=Object.entries(registry).map(([entity,d])=>({entity,source:'mcp/registry.js',native_location:d.section,scope:d.scope,permissions:d.caps,read_fields:d.fields,derived_or_read_only:true,update_instructions:'Only separately registered typed change tools may write. A read field is not a write grant.',ownership:'Canonical SQL + record access checks at read time'}));
 return {version:1,scope:'Explicit registered capabilities; source-discovery backlog is separate and is not covered by this count.',models:modelCatalog,capabilities,record_schemas:records,product_guides:productGuides,automation_actions:automationTestHooks.actionCatalog(),automation_triggers:automationTestHooks.triggerCatalog()};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const path=process.argv[2];if(!path)throw new Error('Usage: node assistant/export-inventory.js OUTPUT [--check]');
 const data=JSON.stringify(inventory(),null,2)+'\n';
 if(process.argv.includes('--check')){if(await readFile(path,'utf8')!==data)throw new Error('Capability inventory is stale. Regenerate and review the schema/coverage change.');}
 else await writeFile(path,data);
 console.log(JSON.stringify({capabilities:inventory().capabilities.length,fields:inventory().capabilities.reduce((n,c)=>n+c.fields.length,0),path}));
}
