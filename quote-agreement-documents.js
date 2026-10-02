import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { PDFDocument, PDFString, PDFDict, PDFArray, PDFName, degrees, rgb } from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import { QuoteContractError, quoteText, quoteInteger } from "./quote-contract-domain.js";

const fail = (code, message) => { throw new QuoteContractError(code, message); };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
let fontBytes;
async function attachFont(pdf) {
  fontBytes ??= await readFile(new URL("./assets/NotoSans.ttf", import.meta.url));
  pdf.registerFontkit(fontkit);
  return pdf.embedFont(fontBytes, { subset: true });
}

export const AGREEMENT_MERGE_FIELDS = Object.freeze({
  customer_name: "Customer name", service_address: "Service address", billing_address: "Billing address",
  customer_phone: "Customer phone", customer_email: "Customer email", business_name: "Business name",
  business_address: "Business address", business_phone: "Business phone", business_email: "Business email",
  quote_number: "Quote number", issue_date: "Issue date", expires_at: "Expiration date",
  services: "Service descriptions", subtotal: "Subtotal", tax: "Tax", total: "Total",
  deposit: "Deposit due", deposit_percentage: "Deposit percentage", balance: "Remaining balance",
  plan_name: "Plan name", service_frequency: "Service frequency", contract_term: "Contract term",
  plan_price: "Plan visit price", billing_information: "Plan billing information",
});

export function resolveAgreementText(text, values) {
  return quoteText(text, "Agreement text", 100000).replace(/\{\{([a-z_]+)\}\}/g, (_match, name) => {
    if (!(name in AGREEMENT_MERGE_FIELDS)) fail("agreement_merge_unknown", `The merge field ${name} is not supported.`);
    if (values[name] == null || values[name] === "") fail("agreement_merge_missing", `Enter ${AGREEMENT_MERGE_FIELDS[name]} before publishing.`);
    return String(values[name]);
  });
}

// Parse the real PDF structure, including object streams, rather than trusting
// MIME/extension or a byte regex that compressed JavaScript could evade.
export async function validateAndNormalizeAgreementPDF(bytes, { allowSanitize = true } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 8 || bytes.length > 10 * 1024 * 1024 || !bytes.subarray(0, 1024).includes(Buffer.from("%PDF-"))) fail("agreement_pdf_invalid", "Upload a valid PDF no larger than 10 MB.");
  let source;
  try { source = await PDFDocument.load(bytes, { updateMetadata: false, throwOnInvalidObject: true }); }
  catch { fail("agreement_pdf_unreadable", "This PDF is corrupt or encrypted. Export an unencrypted PDF and try again."); }
  if (source.isEncrypted) fail("agreement_pdf_encrypted", "Encrypted PDF contracts are not supported.");
  const forbidden = new Set(["JS", "JavaScript", "Launch", "EmbeddedFiles", "EF", "RichMedia", "XFA", "OpenAction", "AA"]);
  const visited = new Set(), removed = new Set();
  const inspect = (object) => {
    if (visited.has(object)) return;
    visited.add(object);
    if (object instanceof PDFDict) {
      for (const [key, value] of object.entries()) {
        const name = key.decodeText();
        if (name === "ByteRange" || (name === "FT" && value.toString() === "/Sig" && object.get(PDFName.of("V")))) fail("agreement_pdf_already_signed", "This PDF contains digital-signature fields or evidence. Preserve its original and upload an unsigned source for this signing workflow.");
        if (forbidden.has(name)) {
          if (!allowSanitize) fail("agreement_pdf_active_content", "The generated quote PDF must contain only its printable content.");
          removed.add(name); object.delete(key); continue;
        }
        if (name === "S" && ["/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/RichMediaExecute", "/GoToR", "/GoToE"].includes(value.toString())) {
          if (!allowSanitize) fail("agreement_pdf_active_content", "The generated quote PDF must contain only its printable content.");
          removed.add("Action"); for (const [entry] of object.entries()) object.delete(entry); break;
        }
        inspect(value);
      }
    } else if (object instanceof PDFArray) object.asArray().forEach(inspect);
    else if (object?.dict instanceof PDFDict) inspect(object.dict);
  };
  for (const [, object] of source.context.enumerateIndirectObjects()) inspect(object);
  // Preserve existing visible form values before discarding interactive widgets.
  // Original source bytes remain private evidence, while only passive pages are delivered.
  if (source.catalog.has(PDFName.of("AcroForm"))) {
    try {
      const form = source.getForm();
      for (const field of form.getFields()) {
        if (field.constructor.name === "PDFSignature") form.removeField(field);
      }
      form.updateFieldAppearances(await attachFont(source));
      form.flatten({ updateFieldAppearances: false });
    } catch { fail("agreement_pdf_form_unreadable", "This PDF's existing form cannot be preserved. Export or print it to a regular PDF, then upload that copy."); }
  }
  const sourcePages = source.getPages();
  if (!sourcePages.length || sourcePages.length > 50) fail("agreement_pdf_pages", "Contracts must contain 1–50 pages.");
  const normalized = await PDFDocument.create();
  const pageSizes = [];
  for (const page of sourcePages) {
    const box = page.getCropBox();
    const rotation = ((page.getRotation().angle % 360) + 360) % 360;
    if (![0, 90, 180, 270].includes(rotation) || box.width < 36 || box.height < 36 || box.width > 14400 || box.height > 14400) fail("agreement_pdf_geometry", "This PDF contains an unsupported page size or rotation.");
    const swapped = rotation === 90 || rotation === 270;
    const width = swapped ? box.height : box.width;
    const height = swapped ? box.width : box.height;
    const target = normalized.addPage([width, height]);
    const origin = rotation === 90 ? { x: 0, y: box.width } : rotation === 180 ? { x: box.width, y: box.height } : rotation === 270 ? { x: box.height, y: 0 } : { x: 0, y: 0 };
    // A valid blank page may omit /Contents entirely. Preserve its geometry
    // instead of passing it to pdf-lib's content-stream embedder.
    if (page.node.Contents()) {
      const embedded = await normalized.embedPage(page, { left: box.x, bottom: box.y, right: box.x + box.width, top: box.y + box.height });
      target.drawPage(embedded, { ...origin, width: box.width, height: box.height, rotate: degrees(-rotation) });
    }
    pageSizes.push({ width, height });
  }
  const result = Buffer.from(await normalized.save());
  return { source_sha256: sha256(bytes), normalized_sha256: sha256(result), normalized: result, pages: pageSizes, removed_features: [...removed] };
}

export function normalizeAgreementFields(raw, pages) {
  if (!Array.isArray(raw) || raw.length > 250) fail("agreement_fields_invalid", "A document supports up to 250 fields.");
  const ids = new Set();
  return raw.map((field) => {
    if (!field || typeof field !== "object" || Array.isArray(field)) fail("agreement_field_invalid", "Each field needs a definition.");
    const id = quoteText(field.id, "Field ID", 80);
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id) || ids.has(id)) fail("agreement_field_id", "Each field must have a unique ID.");
    ids.add(id);
    const page = quoteInteger(field.page, "Field page", pages.length - 1);
    const type = field.type;
    if (!["text", "signature", "initials", "checkbox", "date_signed", "printed_name", "merge"].includes(type)) fail("agreement_field_type", "Choose a supported field type.");
    const role = field.role ?? "customer";
    if (!["customer", "customer_2", "business", "staff"].includes(role)) fail("agreement_field_role", "Choose a supported signer role.");
    if (typeof field.required !== "boolean") fail("agreement_field_required", "Specify whether this field is required.");
    const coordinate = (name) => {
      if (typeof field[name] !== "number" || !Number.isFinite(field[name]) || field[name] < 0 || field[name] > 1) fail("agreement_field_bounds", "Field positions and sizes must be within the page.");
      return field[name];
    };
    const x = coordinate("x"), y = coordinate("y"), width = coordinate("width"), height = coordinate("height");
    if (width <= 0 || height <= 0 || x + width > 1.00000001 || y + height > 1.00000001) fail("agreement_field_bounds", "Keep the entire field inside its page.");
    if (field.rotation != null && field.rotation !== 0) fail("agreement_field_rotation", "Fields stay horizontal; rotation is not supported.");
    const source = field.source ?? null;
    if (type === "merge" && !(source in AGREEMENT_MERGE_FIELDS)) fail("agreement_field_source", "Choose a supported CRM field.");
    if (["signature", "initials", "date_signed", "printed_name"].includes(type) && role === "staff") fail("agreement_field_role", "Signing fields require an identified signer role.");
    return { id, page, type, role, required: field.required, label: quoteText(field.label, "Field label", 200), x, y, width, height, font_size: quoteInteger(field.font_size ?? 11, "Font size", 36, 8), source, value: quoteText(field.value, "Prefilled value", 20000), align: ["left", "center", "right"].includes(field.align) ? field.align : "left" };
  });
}

export function validateAgreementSignature(raw, { requireDrawn = false } = {}) {
  if (!raw || typeof raw !== "object") fail("signature_required", "Enter your signature.");
  if (requireDrawn && raw.type !== "drawn") fail("signature_drawing_required", "Enter your printed name and draw your signature.");
  if (raw.type === "typed") {
    const text = quoteText(raw.text, "Signature", 160).trim();
    if ([...text].filter((letter) => /[\p{L}\p{N}]/u.test(letter)).length < 2) fail("signature_empty", "Enter a meaningful signature with at least two letters or numbers.");
    return { type: "typed", text };
  }
  if (raw.type !== "drawn" || !Array.isArray(raw.strokes) || !raw.strokes.length || raw.strokes.length > 100) fail("signature_invalid", "Draw your signature.");
  let count = 0;
  const points = [];
  const strokes = raw.strokes.map((stroke) => {
    if (!Array.isArray(stroke) || stroke.length < 2) fail("signature_empty", "Draw a complete signature.");
    return stroke.map((point) => {
      if (++count > 10000 || !Array.isArray(point) || point.length !== 2 || point.some((v) => typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1)) fail("signature_invalid", "The signature drawing is invalid.");
      points.push(point);
      return point;
    });
  });
  const xs = points.map((p) => p[0]), ys = points.map((p) => p[1]);
  if (new Set(points.map((p) => p.join(","))).size < 6 || Math.max(...xs) - Math.min(...xs) < 0.04 || Math.max(...ys) - Math.min(...ys) < 0.02) fail("signature_empty", "The drawing is too small to be a meaningful signature. Please draw it again.");
  return { type: "drawn", strokes };
}

export function validateAgreementSubmission(fields, values, { role, printed_name, submitted_at, require_drawn = false }) {
  if (!values || typeof values !== "object" || Array.isArray(values)) fail("agreement_values_invalid", "Signing values must be an object.");
  const allowed = new Map(fields.filter((field) => field.role === role && !["merge", "date_signed"].includes(field.type)).map((field) => [field.id, field]));
  for (const id of Object.keys(values)) if (!allowed.has(id)) fail("agreement_field_unauthorized", "A submitted field does not belong to this signer or document version.");
  const result = {};
  for (const field of fields.filter((field) => field.role === role && field.type !== "merge")) {
    const value = field.type === "date_signed" ? submitted_at : field.type === "printed_name" ? printed_name : values[field.id];
    if (value == null || value === "" || (field.type === "checkbox" && value === false)) {
      if (field.required) fail("agreement_field_missing", `Complete ${field.label || field.id}.`);
      continue;
    }
    if (field.type === "signature") result[field.id] = validateAgreementSignature(value, { requireDrawn: require_drawn });
    else if (field.type === "checkbox") {
      if (typeof value !== "boolean") fail("agreement_checkbox_invalid", "Checkbox values must be true or false.");
      result[field.id] = value;
    } else {
      const text = quoteText(value, field.label || "Field", field.type === "initials" ? 20 : 20000).trim();
      if (field.required && !text) fail("agreement_field_missing", `Complete ${field.label || field.id}.`);
      result[field.id] = text;
    }
  }
  return result;
}

const characterSets = new WeakMap();
function requireSupportedText(text, font) {
  let supported=characterSets.get(font);
  if(!supported){supported=new Set(font.getCharacterSet());characterSets.set(font,supported);}
  for(const character of String(text)) {
    if(/\s/u.test(character)||supported.has(character.codePointAt(0)))continue;
    fail('agreement_font_unsupported',`The document font cannot display “${character}” (U+${character.codePointAt(0).toString(16).toUpperCase()}). Contact the business for a document or signing method that supports this text.`);
  }
}

export async function validateAgreementSignerText(printedName, signature) {
  const pdf=await PDFDocument.create(),font=await attachFont(pdf);
  requireSupportedText(printedName,font);
  if(signature.type==='typed')requireSupportedText(signature.text,font);
}

function wrap(text, font, size, maxWidth) {
  requireSupportedText(text,font);
  const output = [];
  if(maxWidth <= 0)fail("agreement_field_overflow","Enlarge this field before placing text in it.");
  for (const paragraph of String(text).split("\n")) {
    if (!paragraph) { output.push(""); continue; }
    let line = "";
    for (const token of paragraph.match(/\S+\s*|\s+/gu) || []) {
      if(font.widthOfTextAtSize(line+token,size)<=maxWidth){line+=token;continue;}
      if(line){output.push(line);line="";}
      if(font.widthOfTextAtSize(token,size)<=maxWidth){line=token;continue;}
      // Only an unbroken address/URL needs code-point wrapping. Whitespace and
      // exact content remain preserved; ordinary words stay together.
      for(const character of token){
        if(font.widthOfTextAtSize(character,size)>maxWidth)fail("agreement_field_overflow","Text does not fit this field. Enlarge it or reduce its font size.");
        if(font.widthOfTextAtSize(line+character,size)>maxWidth&&line){output.push(line);line="";}
        line+=character;
      }
    }
    output.push(line);
  }
  return output;
}

export async function populateAgreementPDF(bytes, fields, values) {
  const pdf = await PDFDocument.load(bytes);
  const font = await attachFont(pdf);
  for (const field of fields) {
    const value = values[field.id];
    if (value == null || value === "") continue;
    const page = pdf.getPage(field.page);
    const { width: pw, height: ph } = page.getSize();
    const x = field.x * pw, top = ph - field.y * ph, width = field.width * pw, height = field.height * ph;
    if (field.type === "signature" && value.type === "drawn") {
      // Input drawing canvas ratio is 3:1; fit it without stretching.
      const dw = Math.min(width, height * 3), dh = dw / 3;
      for (const stroke of value.strokes) for (let i = 1; i < stroke.length; i++) page.drawLine({ start: { x: x + stroke[i - 1][0] * dw, y: top - stroke[i - 1][1] * dh }, end: { x: x + stroke[i][0] * dw, y: top - stroke[i][1] * dh }, thickness: 1.3, color: rgb(0.08, 0.12, 0.22) });
      continue;
    }
    const text = field.type === "checkbox" ? (value===true||value==='true' ? "X" : "") : field.type === "signature" ? value.text : String(value);
    const rows = wrap(text, font, field.font_size, width - 4);
    const leading = field.font_size * 1.35;
    if (rows.length * leading > height - 2) fail("agreement_field_overflow", `${field.label || field.id} does not fit its field. Enlarge it or use a smaller font before signing.`);
    rows.forEach((line, index) => {
      const textWidth = font.widthOfTextAtSize(line, field.font_size);
      const offset = field.align === "right" ? width - textWidth - 2 : field.align === "center" ? (width - textWidth) / 2 : 2;
      page.drawText(line, { x: x + offset, y: top - field.font_size - index * leading, font, size: field.font_size, color: rgb(0.06, 0.09, 0.14) });
    });
  }
  return Buffer.from(await pdf.save());
}

const money = (cents) => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);

export async function generateQuoteAgreementPDF(snapshot, { customer_url, signatures = [], audit = false } = {}) {
  const pdf = await PDFDocument.create();
  pdf.setTitle(`${snapshot.title || "Estimate"} ${snapshot.number || ""}`);
  pdf.setCreator("WolfCRM");
  const font = await attachFont(pdf);
  let page, y;
  const newPage = () => { page = pdf.addPage([612, 792]); y = 742; };
  newPage();
  const accent=snapshot.branding?.accent_color;
  if(/^#[0-9a-f]{6}$/i.test(accent||''))page.drawRectangle({x:50,y:755,width:512,height:4,color:rgb(...[1,3,5].map(index=>parseInt(accent.slice(index,index+2),16)/255))});
  if(snapshot.business?.logo_data_url){
    const match=/^data:image\/(png|jpe?g);base64,([A-Za-z0-9+/=]+)$/.exec(snapshot.business.logo_data_url);
    if(!match||match[2].length>5600000)fail("agreement_logo_invalid","Choose a PNG or JPEG business logo no larger than 4 MB.");
    let logo;
    try{const bytes=Buffer.from(match[2],"base64");if(match[1]==="png"&&(bytes.length<24||bytes.readUInt32BE(16)>4096||bytes.readUInt32BE(20)>4096))fail("agreement_logo_invalid","Resize the PNG logo to 4096 pixels or less per side.");logo=match[1]==="png"?await pdf.embedPng(bytes):await pdf.embedJpg(bytes);}catch{fail("agreement_logo_invalid","The business logo could not be read. Upload a PNG or JPEG up to 4096 pixels per side.");}
    if(logo.width>4096||logo.height>4096||logo.width*logo.height>16777216)fail("agreement_logo_invalid","Resize the business logo to 4096 pixels or less per side.");
    const scale=Math.min(180/logo.width,64/logo.height);
    page.drawImage(logo,{x:50,y:y-logo.height*scale,width:logo.width*scale,height:logo.height*scale});
    y-=logo.height*scale+16;
  }
  const paragraph = (text, size = 11) => {
    const lines = wrap(String(text ?? ""), font, size, 512);
    for (const line of lines) {
      if (y < 55 + size * 1.4) newPage();
      page.drawText(line, { x: 50, y: y - size, font, size, color: rgb(0.06, 0.09, 0.14) });
      y -= size * 1.4;
    }
    y -= 7;
  };
  paragraph(snapshot.business?.name || "Service estimate", 22);
  paragraph(`${snapshot.estimate_label||'Estimate'} #${snapshot.number || ""} · Revision ${snapshot.revision || 1}`, 16);
  if(snapshot.title&&snapshot.title!==snapshot.estimate_label)paragraph(snapshot.title,14);
  paragraph(`Service from: ${[snapshot.business?.name, snapshot.business?.address, snapshot.business?.phone, snapshot.business?.email].filter(Boolean).join(" • ")}`);
  paragraph(`Prepared for: ${[snapshot.customer?.name, snapshot.customer?.address, snapshot.customer?.phone, snapshot.customer?.email].filter(Boolean).join(" • ")}`);
  if(snapshot.customer?.billing_address&&snapshot.customer.billing_address!==snapshot.customer.address)paragraph(`Billing address: ${snapshot.customer.billing_address}`);
  if (snapshot.issued_at) paragraph(`Issued: ${snapshot.issued_at}`);
  if (snapshot.expires_at) paragraph(`Offer expires: ${snapshot.expires_at}`);
  for (const [index, item] of (snapshot.pricing?.line_items || []).entries()) {
    paragraph(`${index + 1}. ${item.name} — ${item.qty} × ${money(item.price_cents)} = ${money(item.total_cents)}`, 12);
    if (item.description) paragraph(item.description);
  }
  if (snapshot.pricing) {
    const p = snapshot.pricing;
    paragraph(`Subtotal: ${money(p.subtotal_cents)}\nDiscount: ${money(p.discount_cents)}\nTax${p.tax_inclusive ? " (included)" : ""}: ${money(p.tax_cents)}\nTotal: ${money(p.total_cents)}\nDeposit due after signing: ${money(p.deposit_cents)}\nBalance after deposit: ${money(p.total_cents - p.deposit_cents)}`, 12);
    paragraph(snapshot.balance_payment_timing==='after_service'?'Remaining balance collection opens after the quoted service is completed.':'Remaining balance may be paid after all required signing and deposit steps.');
    if(snapshot.balance_due_days_after_service!=null)paragraph(`Remaining balance is due ${snapshot.balance_due_days_after_service} days after completion of the quoted service.`);
    if(snapshot.optional_addons?.length){
      paragraph("Optional services",14);
      paragraph(snapshot.addon_selection_finalized ? "Selected options are included in the estimate scope and total above. Other options are not included." : "These choices are not included in the current total. Finalize your choices on the estimate page before signing.");
      for(const option of snapshot.optional_addons){
        paragraph(`${snapshot.selected_addon_ids?.includes(option.id)?"Selected":"Not included"}: ${option.name} — ${option.qty} × ${money(option.price_cents)} before any applicable tax`,12);
        if(option.description)paragraph(option.description);
      }
    }
  }
  if (snapshot.public_notes) { paragraph("Notes", 14); paragraph(snapshot.public_notes); }
  if (snapshot.scope_exclusions) { paragraph("Not included / Scope exclusions", 14); paragraph(snapshot.scope_exclusions); }
  if (snapshot.agreement_text) { paragraph("Agreement", 14); paragraph(snapshot.agreement_text); }
  if (snapshot.terms_text) { paragraph("Terms & Conditions", 14); paragraph(snapshot.terms_text); }
  if (snapshot.documents?.length) {
    paragraph("Included contract documents", 14);
    snapshot.documents.forEach((document) => paragraph(`${document.name}\nDocument integrity hash: ${document.sha256}`, 9));
  }
  if (snapshot.terms_document) paragraph(`Terms & Conditions: ${snapshot.terms_document.name}\nDocument integrity hash: ${snapshot.terms_document.sha256}`, 9);
  if (snapshot.consent_text) { paragraph("Electronic signing consent", 14); paragraph(snapshot.consent_text); }
  for (const signature of signatures) {
    paragraph(`Submitted by ${signature.printed_name} (${signature.role})`, 14);
    paragraph(`Submitted: ${signature.submitted_at}\nVerification: ${signature.verification_method || "Link access only"}`);
    if (signature.signature.type === "typed") paragraph(`Signature: ${signature.signature.text}`, 18);
    else {
      if (y < 160) newPage();
      for (const stroke of signature.signature.strokes) for (let i = 1; i < stroke.length; i++) page.drawLine({ start: { x: 50 + stroke[i - 1][0] * 300, y: y - stroke[i - 1][1] * 100 }, end: { x: 50 + stroke[i][0] * 300, y: y - stroke[i][1] * 100 }, thickness: 1.3 });
      y -= 115;
    }
    if (audit) paragraph(`Packet hash: ${signature.packet_hash}\nSession: ${signature.session_id}\nBackend-observed request IP (may identify a proxy): ${signature.source_ip || "Not recorded"}\nUnverified user-agent header: ${signature.user_agent || "Not recorded"}\nNetwork observations do not verify customer location, device, or identity; the recorded verification method remains authoritative.`);
  }
  if (customer_url) {
    if (!/^https:\/\//.test(customer_url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|\/)/.test(customer_url)) fail("agreement_url_invalid", "The estimate link must use HTTPS.");
    if (y < 90) newPage();
    const label = signatures.length ? "View estimate and completed documents online" : "View Estimate Online / Return to Sign";
    paragraph(label, 11);
    const annotation = pdf.context.obj({ Type: "Annot", Subtype: "Link", Rect: [50, y, 562, y + 24], Border: [0, 0, 0], A: { S: "URI", URI: PDFString.of(customer_url) } });
    page.node.addAnnot(pdf.context.register(annotation));
  }
  const pages = pdf.getPages();
  pages.forEach((p, index) => p.drawText(`${index + 1} / ${pages.length}`, { x: 540, y: 25, font, size: 9 }));
  return Buffer.from(await pdf.save());
}

export { sha256 as agreementBytesHash };

export async function combineAgreementPDFs(documents) {
  const output = await PDFDocument.create();
  for (const bytes of documents) {
    const source = await PDFDocument.load(bytes);
    const pages = await output.copyPages(source, source.getPageIndices());
    pages.forEach((page) => output.addPage(page));
  }
  return Buffer.from(await output.save());
}

// A delivery copy may return only to its own recipient role. The stored source
// artifact and all page content/signature streams remain untouched.
export async function qualifyAgreementDocumentLinks(bytes, { agreement_id, customer_url }) {
  const target = new URL(customer_url);
  if (!target.pathname.startsWith(`/estimates/${agreement_id}.`)) fail('agreement_document_link_invalid', 'The document return link does not match its agreement.');
  const pdf = await PDFDocument.load(bytes, { updateMetadata: false });
  let changed = false;
  for (const page of pdf.getPages()) {
    const annotations=page.node.Annots();
    for (let index=0;annotations&&index<annotations.size();index++) {
      const annotation=pdf.context.lookup(annotations.get(index));
      if (!(annotation instanceof PDFDict)) continue;
      const action=annotation.lookup(PDFName.of('A'));
      if (!(action instanceof PDFDict)||String(action.lookup(PDFName.of('S')))!=='/URI') continue;
      const value=action.lookup(PDFName.of('URI'));
      if (typeof value?.decodeText!=='function') continue;
      let url;try{url=new URL(value.decodeText());}catch{continue;}
      if (!url.pathname.startsWith(`/estimates/${agreement_id}.`)||url.href===target.href) continue;
      action.set(PDFName.of('URI'),PDFString.of(target.href));changed=true;
    }
  }
  return changed?Buffer.from(await pdf.save()):bytes;
}
