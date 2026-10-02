import test from "node:test";
import assert from "node:assert/strict";
import { PDFDocument, PDFName, degrees } from "pdf-lib";
import { validateAndNormalizeAgreementPDF, normalizeAgreementFields, validateAgreementSignature, validateAgreementSubmission, populateAgreementPDF, generateQuoteAgreementPDF, resolveAgreementText, validateAgreementSignerText } from "../quote-agreement-documents.js";
import { calculateQuotePricing } from "../quote-contract-domain.js";

async function sourcePDF(rotation = 0) {
  const doc = await PDFDocument.create();
  const page = doc.addPage([612, 792]);
  page.drawText("Original source contract");
  page.setRotation(degrees(rotation));
  return doc;
}
const definition = (extra = {}) => ({ id: "signature", page: 0, type: "signature", role: "customer", required: true, label: "Customer signature", x: 0.1, y: 0.5, width: 0.7, height: 0.15, ...extra });

test("PDF normalization preserves original bytes and normalizes rotated/cropped coordinate space", async () => {
  for (const rotation of [0, 90, 180, 270]) {
    const doc = await sourcePDF(rotation);
    doc.getPage(0).setCropBox(12, 15, 500, 700);
    const bytes = Buffer.from(await doc.save());
    const original = Buffer.from(bytes);
    const normalized = await validateAndNormalizeAgreementPDF(bytes);
    assert.deepEqual(bytes, original);
    assert.deepEqual(normalized.pages[0], rotation % 180 ? { width: 700, height: 500 } : { width: 500, height: 700 });
    const reloaded = await PDFDocument.load(normalized.normalized);
    assert.equal(reloaded.getPage(0).getRotation().angle, 0);
  }
});

test("valid blank PDF pages retain geometry and accept later signing fields",async()=>{
  const doc=await PDFDocument.create();doc.addPage([612,792]);
  const normalized=await validateAndNormalizeAgreementPDF(Buffer.from(await doc.save()));
  assert.deepEqual(normalized.pages,[{width:612,height:792}]);
  const fields=normalizeAgreementFields([definition()],normalized.pages);
  const filled=await populateAgreementPDF(normalized.normalized,fields,{signature:{type:"typed",text:"Customer"}});
  assert.equal((await PDFDocument.load(filled)).getPageCount(),1);
});

test("actual PDF parsing rejects compressed scripts, signed inputs, attachments and corrupt content", async () => {
  for (const [key, value] of [["OpenAction", { S: "JavaScript", JS: "alert(1)" }], ["ByteRange", [0, 1, 2, 3]], ["EmbeddedFiles", {}]]) {
    const doc = await sourcePDF();
    doc.catalog.set(PDFName.of(key), doc.context.obj(value));
    await assert.rejects(validateAndNormalizeAgreementPDF(Buffer.from(await doc.save())), /scripts|digital-signature/);
  }
  await assert.rejects(validateAndNormalizeAgreementPDF(Buffer.from("%PDF-corrupt")), /corrupt/);
  await assert.rejects(validateAndNormalizeAgreementPDF(Buffer.from("image.png")), /valid PDF/);
});

test("field definitions enforce page/bounds/role/type and prohibit rotation", () => {
  const pages = [{ width: 612, height: 792 }];
  for (const field of [definition({ x: 0.9 }), definition({ page: 1 }), definition({ rotation: 45 }), definition({ role: "admin" }), definition({ type: "merge", source: "internal_notes" })]) assert.throws(() => normalizeAgreementFields([field], pages));
  assert.equal(normalizeAgreementFields([definition()], pages)[0].font_size, 11);
});

test("blank signatures, fake images, malformed drawings and wrong-role fields cannot submit", () => {
  for (const signature of [{ type: "typed", text: "  " }, { type: "typed", text: ".." }, { type: "drawn", strokes: [[[0, 0], [0, 0]]] }, { type: "image", data: "blank" }]) assert.throws(() => validateAgreementSignature(signature));
  const fields = normalizeAgreementFields([definition(), definition({ id: "consent", type: "checkbox" }), definition({ id: "date", type: "date_signed" })], [{ width: 612, height: 792 }]);
  const context = { role: "customer", printed_name: "Alex Customer", submitted_at: "2026-10-01T10:00:00Z" };
  assert.throws(() => validateAgreementSubmission(fields, {}, context), /Complete/);
  assert.throws(() => validateAgreementSubmission(fields, { price: 1 }, context), /does not belong/);
  assert.throws(() => validateAgreementSubmission(fields, { signature: { type: "typed", text: "Alex" }, consent: false }, context), /Complete/);
  const values = validateAgreementSubmission(fields, { signature: { type: "typed", text: "Alex" }, consent: true }, context);
  assert.equal(values.date, context.submitted_at);
});

test("populated PDFs contain signable field output; overflow fails instead of truncating", async () => {
  const source = await sourcePDF();
  const bytes = Buffer.from(await source.save());
  const fields = normalizeAgreementFields([definition()], [{ width: 612, height: 792 }]);
  const output = await populateAgreementPDF(bytes, fields, { signature: { type: "typed", text: "Alex García" } });
  assert.equal((await PDFDocument.load(output)).getPageCount(), 1);
  const small = normalizeAgreementFields([definition({ type: "text", width: 0.01, height: 0.01 })], [{ width: 612, height: 792 }]);
  await assert.rejects(populateAgreementPDF(bytes, small, { signature: "Long customer name" }), /does not fit/);
});

test("generated quote records paginate long descriptions, retain exact price and have working return links", async () => {
  const pricing = calculateQuotePricing({ line_items: Array.from({ length: 40 }, (_, i) => ({ name: `Window ${i + 1}`, qty: 1, price_cents: 1500, description: "Work scope and exclusions. ".repeat(20) })) });
  const bytes = await generateQuoteAgreementPDF({ number: "E-42", business: { name: "Business" }, customer: { name: "Alex García" }, pricing, consent_text: "I agree to electronic signing." }, { customer_url: "https://quotes.example.test/estimates/token" });
  const pdf = await PDFDocument.load(bytes);
  assert.ok(pdf.getPageCount() > 5);
  const page = pdf.getPages().find((page) => page.node.Annots()?.size());
  const annot = pdf.context.lookup(page.node.Annots().get(0));
  assert.equal(annot.lookup(PDFName.of("A")).lookup(PDFName.of("URI")).decodeText(), "https://quotes.example.test/estimates/token");
});

test("controlled merges reject missing required data and never substitute private notes", () => {
  assert.equal(resolveAgreementText("Hello {{customer_name}}", { customer_name: "Alex" }), "Hello Alex");
  assert.throws(() => resolveAgreementText("{{internal_notes}}", {}), /not supported/);
  assert.throws(() => resolveAgreementText("{{service_address}}", {}), /Enter Service address/);
});

test('unsupported document glyphs fail explicitly before losing name/signature content',async()=>{
  await validateAgreementSignerText('Alex García',{type:'typed',text:'Alex García'});
  await assert.rejects(validateAgreementSignerText('Name 😀',{type:'typed',text:'Name 😀'}),error=>error.code==='agreement_font_unsupported');
  await assert.rejects(generateQuoteAgreementPDF({number:'1',business:{name:'Unsupported 😀'}}),error=>error.code==='agreement_font_unsupported');
  const doc=await sourcePDF(),bytes=await doc.save();
  const fields=normalizeAgreementFields([definition({type:'text'})],[{width:612,height:792}]);
  await assert.rejects(populateAgreementPDF(bytes,fields,{signature:'Name 😀'}),error=>error.code==='agreement_font_unsupported');
});

test('new customer signature fields require drawings while historical typed evidence remains renderable', () => {
  const typed = {type:'typed',text:'Customer'};
  assert.equal(validateAgreementSignature(typed).type,'typed');
  assert.throws(()=>validateAgreementSignature(typed,{requireDrawn:true}),error=>error.code==='signature_drawing_required');
  assert.throws(()=>validateAgreementSubmission([definition()],{signature:typed},{role:'customer',printed_name:'Customer',submitted_at:'2026-10-02T00:00:00Z',require_drawn:true}),error=>error.code==='signature_drawing_required');
});
