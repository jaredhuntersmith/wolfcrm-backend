// Browser contracts never fetch websites or accept client cookies/authorization headers.
export function safeWebpage(raw) {
  let url;
  try { url = new URL(raw?.url ?? raw?.source_id); } catch { throw Object.assign(new Error('invalid_webpage_url'), {status:400}); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.href.length > 4096) throw Object.assign(new Error('invalid_webpage_url'), {status:400});
  const title = typeof raw?.title === 'string' ? raw.title.trim().slice(0,300) : url.hostname;
  return {url:url.href,title:title || url.hostname,domain:url.hostname};
}
export function browserAIInput(raw) {
  if (!['summarize','explain','extract','questions','pricing','contacts','products','tasks','compare'].includes(raw?.action)) throw Object.assign(new Error('invalid_browser_action'),{status:400});
  if (!Array.isArray(raw.pages) || !raw.pages.length || raw.pages.length > 5) throw Object.assign(new Error('invalid_browser_pages'),{status:400});
  if (raw.action === 'compare' && raw.pages.length < 2) throw Object.assign(new Error('compare_requires_two_pages'),{status:400});
  let length = 0;
  const pages = raw.pages.map(page => {
    const source = safeWebpage(page);
    if (typeof page.text !== 'string' || !page.text.trim() || page.text.length > 60000) throw Object.assign(new Error('invalid_browser_text'),{status:400});
    length += page.text.length;
    return {...source,text:page.text};
  });
  if (length > 100000) throw Object.assign(new Error('browser_text_too_large'),{status:413});
  return {action:raw.action,pages,question:typeof raw.question === 'string' ? raw.question.slice(0,2000) : ''};
}
