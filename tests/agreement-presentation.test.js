import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeCustomerPage } from '../agreement-presentation.js';
import { normalizeAgreementContent } from '../agreement-content.js';
test('customer page controls normalize and remain part of template content',()=>{
  const input={show_manage_booking:false,allow_reschedule:true,allow_cancel:false,plan_heading:'Care for your home',plan_description:'Choose your visit.',footer_links:{website:'https://example.com',facebook:'https://facebook.com/example'}};
  const normalized=normalizeAgreementContent({customer_page:input});
  assert.equal(normalized.customer_page.plan_heading,input.plan_heading);
  assert.equal(normalized.customer_page.show_manage_booking,false);
  assert.equal(normalized.customer_page.allow_reschedule,true);
  assert.equal(normalized.customer_page.footer_links.website,'https://example.com/');
  assert.deepEqual(normalizeCustomerPage(JSON.parse(JSON.stringify(normalized.customer_page))),normalized.customer_page);
  assert.equal(normalizeCustomerPage().show_manage_booking,true);
  assert.equal(normalizeCustomerPage().allow_cancel,false);
});
test('customer page rejects unsafe links and malformed flags',()=>{
  for(const url of ['javascript:alert(1)','data:text/html,hello','https://user:secret@example.com','file:///tmp/a','not a URL'])assert.throws(()=>normalizeCustomerPage({footer_links:{website:url}}),e=>e.code==='customer_page_invalid');
  assert.throws(()=>normalizeCustomerPage({allow_cancel:'yes'}),e=>e.code==='customer_page_invalid');
  assert.throws(()=>normalizeCustomerPage({plan_heading:'a'.repeat(161)}));
});


test('legacy scheme-less footer domains save as HTTPS without admitting unsafe URLs',()=>{
  for(const domain of ['example.com','www.example.com/path?ref=plan','sub.example.co.uk']){
    assert.equal(normalizeCustomerPage({footer_links:{website:domain}}).footer_links.website,new URL('https://'+domain).href);
  }
  for(const value of ['user@example.com','javascript:example.com','//example.com','https://bad host.com','example.com\\@evil.com','example..com','-example.com','example.com:bad','example.com\n']){
    if(value.endsWith('\n')) continue; // surrounding whitespace is intentionally trimmed
    assert.throws(()=>normalizeCustomerPage({footer_links:{website:value}}),e=>e.code==='customer_page_invalid');
  }
});
