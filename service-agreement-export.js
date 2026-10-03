import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import { readFile } from 'node:fs/promises';
import { drawServiceAgreement } from './quote-document-renderer.mjs';

export const SIGNED_PRESENTATION_KIND = 'signed-presentation-v1';
let fallbackBytes;

// Canvas drawing operations shared with the browser export, rendered as vector
// PDF text/paths instead of raster screenshots. Coordinates remain top-down.
class PDFCanvas {
  constructor(page, fonts) { this.page=page; this.fonts=fonts; this.font='400 11px Arial'; this.fillStyle='#000000'; this.strokeStyle='#000000'; this.lineWidth=1; this.textAlign='left'; this.path=[]; }
  textStyle(text) {
    const [,weight,size] = /^(\d+) ([\d.]+)px/.exec(this.font);
    let font=Number(weight)>=600?this.fonts.bold:this.fonts.regular;
    try { font.encodeText(text); } catch { font=this.fonts.fallback; }
    return {font,size:Number(size)};
  }
  color(value) {
    // Native export uses neutral ink and gray table/labels.
    const colors={'#263229':'#111111','#718078':'#999999','#7d867f':'#888888','#758078':'#888888','#6f7972':'#888888','#4f5c53':'#555555','#b7beb8':'#b3b3b3','#aeb7b0':'#b3b3b3'};
    const hex=(colors[value] || value).replace('#','');
    return rgb(parseInt(hex.slice(0,2),16)/255,parseInt(hex.slice(2,4),16)/255,parseInt(hex.slice(4,6),16)/255);
  }
  measureText(value) { const {font,size}=this.textStyle(value); return {width:font.widthOfTextAtSize(value,size)}; }
  fillText(value,x,y) {
    if (!value) return;
    const {font,size}=this.textStyle(value),width=font.widthOfTextAtSize(value,size);
    const adjustment=this.textAlign==='right'?width:this.textAlign==='center'?width/2:0;
    this.page.drawText(value,{x:x-adjustment,y:792-y-font.heightAtSize(size,{descender:false}),font,size,color:this.color(this.fillStyle)});
  }
  fillRect(x,y,width,height) { this.page.drawRectangle({x,y:792-y-height,width,height,color:this.color(this.fillStyle)}); }
  strokeRect(x,y,width,height) { this.page.drawRectangle({x,y:792-y-height,width,height,borderWidth:this.lineWidth,borderColor:this.color(this.strokeStyle)}); }
  beginPath() { this.path=[]; }
  moveTo(x,y) { this.path.push({x,y,move:true}); }
  lineTo(x,y) { this.path.push({x,y}); }
  stroke() { for(let i=1;i<this.path.length;i++){const previous=this.path[i-1],point=this.path[i];if(!point.move)this.page.drawLine({start:{x:previous.x,y:792-previous.y},end:{x:point.x,y:792-point.y},thickness:this.lineWidth,color:this.color(this.strokeStyle)});} }
  drawImage(image,x,y,width,height) {
    const scale=Math.min(width/image.width,height/image.height),w=image.width*scale,h=image.height*scale;
    this.page.drawImage(image,{x:x+(width-w)/2,y:792-y-h,width:w,height:h});
  }
}

export async function generateServiceAgreementPDF(snapshot, signatures=[]) {
  if (!snapshot.pricing) throw new Error('A priced quote is required for the service agreement export.');
  const pdf=await PDFDocument.create(); pdf.registerFontkit(fontkit);
  fallbackBytes ??= readFile(new URL('./assets/NotoSans.ttf',import.meta.url));
  const fonts={regular:await pdf.embedFont(StandardFonts.Helvetica),bold:await pdf.embedFont(StandardFonts.HelveticaBold),fallback:await pdf.embedFont(await fallbackBytes,{subset:true})};
  let logo=null;
  const data=snapshot.business.logo_data_url;
  if (data && data.length<=350000) {
    try { if(/^data:image\/png;base64,/i.test(data)) logo=await pdf.embedPng(data); else if(/^data:image\/jpe?g;base64,/i.test(data)) logo=await pdf.embedJpg(data); } catch { /* A legacy invalid logo must not hide the signed document. */ }
  }
  const business=snapshot.business, pricing=snapshot.pricing;
  const document={
    contact:snapshot.customer,
    quote:{created_at:snapshot.issued_at,total_cents:pricing.total_cents,line_items:pricing.line_items,quote_options:{}},
    settings:{company_name:business.name,company_address:business.address,phone:business.phone,email:business.email,website:business.website,tagline:'Thank you for your business!',tax_enabled:pricing.tax_rate_basis_points>0,tax_rate_basis_points:pricing.tax_rate_basis_points,valid_for_days:30},
    pricing, logo, agreementText:snapshot.agreement_text || '',
  };
  drawServiceAgreement(()=>new PDFCanvas(pdf.addPage([612,792]),fonts),document,signatures);
  pdf.setTitle('Service Agreement'); pdf.setAuthor(business.name || ''); pdf.setCreator('WolfCRM');
  // Keep metadata stable across regeneration; preserve the document's issue date.
  if(snapshot.issued_at && Number.isFinite(Date.parse(snapshot.issued_at))) { pdf.setCreationDate(new Date(snapshot.issued_at));pdf.setModificationDate(new Date(snapshot.issued_at)); }
  return Buffer.from(await pdf.save());
}
