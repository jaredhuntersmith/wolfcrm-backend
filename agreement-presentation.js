import { QuoteContractError, quoteText } from './quote-contract-domain.js';
export const planHeading = 'Choose your service';
export const planDescription = 'Stay with a one-time visit or choose ongoing care. Your choice is confirmed only when you complete checkout.';
export function normalizeCustomerPage(raw = {}) {
  const fail=message=>{throw new QuoteContractError('customer_page_invalid',message,400);};
  if(!raw || typeof raw!=='object'||Array.isArray(raw))fail('Enter valid customer page settings.');
  const flag=(name,fallback)=>{if(raw[name]!=null&&typeof raw[name]!=='boolean')fail(`${name} must be on or off.`);return raw[name]??fallback;};
  const footer_links=normalizeFooterLinks(raw.footer_links??{});
  return {show_manage_booking:flag('show_manage_booking',true),allow_reschedule:flag('allow_reschedule',false),allow_cancel:flag('allow_cancel',false),plan_heading:quoteText(raw.plan_heading??planHeading,'Plan heading',160),plan_description:quoteText(raw.plan_description??planDescription,'Plan description',1200),footer_links};
}

export function normalizeFooterLinks(raw = {}) {
  const fail=message=>{throw new QuoteContractError('customer_page_invalid',message,400);};
  const links=raw;
  if(!links||typeof links!=='object'||Array.isArray(links))fail('Enter valid footer links.');
  return Object.fromEntries(['website','facebook','instagram','google_reviews'].map(name=>{
    const text=quoteText(links[name],`${name} URL`,2000).trim();
    if(!text)return[name,''];
    // Older editors copied company domains without a scheme into tier drafts.
    // Normalize only clear DNS names; never turn an arbitrary scheme or userinfo
    // into an apparently safe link. No network request is made here.
    const bareDomain=/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::[0-9]{1,5})?(?:[/?#][^\s\\]*)?$/i.test(text);
    let url;try{url=new URL(bareDomain ? `https://${text}` : text);}catch{fail(`Enter a complete website URL for ${name}.`);}
    if(!['https:','http:'].includes(url.protocol)||!url.hostname||url.username||url.password)fail(`Use an http or https URL for ${name}.`);
    return[name,url.href];
  }));
}
