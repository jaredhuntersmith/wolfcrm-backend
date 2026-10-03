import test from 'node:test';
import assert from 'node:assert/strict';
import { PDFDocument, PDFName, PDFArray, decodePDFRawStream } from 'pdf-lib';
import { generateServiceAgreementPDF } from '../service-agreement-export.js';
import { drawnSignature } from './helpers/signatures.js';

const snapshot=()=>({business:{name:'Window Wolves',phone:'5025550100',email:'office@example.invalid',website:'windowwolves.example'},customer:{name:'Sample Customer',address:'123 Main Street'},issued_at:'2026-10-02T12:00:00Z',agreement_text:'You agree to the quoted services for $875.00.',pricing:{subtotal_cents:87500,total_cents:87500,discount_cents:0,tax_cents:0,tax_rate_basis_points:0,deposit_cents:0,line_items:[{id:'test',name:'Exterior Window Cleaning',description:'Clean exterior glass, frames and sills.',qty:1,price_cents:87500,line_total_cents:87500}]}});
const signer=()=>({printed_name:'Sample Customer',role:'customer',submitted_at:'2026-10-02T12:05:00Z',signature:drawnSignature()});
function pageOperators(pdf,page){const content=page.node.lookup(PDFName.of('Contents'));const streams=content instanceof PDFArray?content.asArray().map(ref=>pdf.context.lookup(ref)):[content];return streams.map(stream=>Buffer.from(decodePDFRawStream(stream).decode()).toString()).join('\n');}
function text(operators){return [...operators.matchAll(/<([0-9A-F]+)> Tj/gi)].map(match=>Buffer.from(match[1],'hex').toString('latin1')).join('\n');}

test('signed export reuses quote layout with service description, agreement and actual signature on first page',async()=>{
  const pdf=await PDFDocument.load(await generateServiceAgreementPDF(snapshot(),[signer()]));
  assert.equal(pdf.getPageCount(),1);
  const operators=pageOperators(pdf,pdf.getPage(0)),content=text(operators);
  for(const value of ['SERVICE AGREEMENT','October 2, 2026','Thank you for your business!','Clean exterior glass, frames and sills.','AGREEMENT','Sample Customer','Customer signature','Signed October 2, 2026','$875.00']) assert.ok(content.includes(value),value);
  assert.doesNotMatch(content,/VALID FOR|30 Days|opportunity|Verification|Document integrity/);
  assert.ok([...operators.matchAll(/\n[\d.]+ [\d.]+ l\n/g)].length>=7,'saved signature drawing paths are present');
  assert.ok(content.indexOf('AGREEMENT\nYou agree')<content.indexOf('Customer signature'));
});
test('long services and agreements paginate without dropping descriptions or additional signers',async()=>{
  const value=snapshot();value.pricing.line_items[0].description=Array.from({length:180},(_,i)=>`Description ${i}: wash glass and frames.`).join('\n');
  value.agreement_text=Array.from({length:160},(_,i)=>`Clause ${i}: the agreed work and payment terms.`).join('\n');
  const pdf=await PDFDocument.load(await generateServiceAgreementPDF(value,[signer(),{...signer(),printed_name:'Second Customer',role:'customer_2'},{...signer(),printed_name:'Business Owner',role:'business'}]));
  assert.ok(pdf.getPageCount()>5);const content=pdf.getPages().map(page=>text(pageOperators(pdf,page))).join('\n');
  for(const value of ['Description 0:','Description 179:','Clause 0:','Clause 159:','Second Customer','Additional customer signature','Business Owner','Business signature'])assert.ok(content.includes(value),value);
});
test('PDF-only signature and historical typed evidence remain visible; unsupported characters fail explicitly',async()=>{
  const value=snapshot();value.agreement_text='';
  const pdf=await PDFDocument.load(await generateServiceAgreementPDF(value,[{...signer(),signature:null,field_values:{signed:drawnSignature()}}]));
  assert.equal(pdf.getPageCount(),1);
  const legacy=await PDFDocument.load(await generateServiceAgreementPDF(value,[{...signer(),signature:{type:'typed',text:'Historic Signer'}}]));
  assert.match(text(pageOperators(legacy,legacy.getPage(0))),/Historic Signer/);
  value.customer.name='Unsupported \u{1F680}';
  await assert.rejects(generateServiceAgreementPDF(value,[signer()]),/unsupported character/);
});
