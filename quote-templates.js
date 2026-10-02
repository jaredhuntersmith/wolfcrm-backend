import { randomUUID } from 'node:crypto';
import { normalizeAgreementContent } from './agreement-content.js';
import { QuoteContractError, QUOTE_TEMPLATE_OPTION_KEYS, normalizeQuoteOptions, normalizeQuoteTemplateDefaults, quoteContentHash } from './quote-contract-domain.js';

const fail = (code, message, status = 400) => { throw new QuoteContractError(code, message, status); };
const validID = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export async function quoteTemplateTransaction(pool, work) {
  const db = await pool.connect();
  try { await db.query('BEGIN'); const result = await work(db); await db.query('COMMIT'); return result; }
  catch (error) { await db.query('ROLLBACK'); throw error; }
  finally { db.release(); }
}
export function completeTemplateContent(raw = {}) {
  const content = normalizeAgreementContent(raw);
  content.quote_defaults = normalizeQuoteTemplateDefaults(content.quote_defaults ?? {
    allow_customer_booking: content.booking_preference ?? false,
    offer_service_plans: content.plan_offer_preference ?? false,
  });
  content.booking_preference = content.quote_defaults.allow_customer_booking;
  content.plan_offer_preference = content.quote_defaults.offer_service_plans;
  return content;
}

// Caller owns a short transaction. Company lock serializes first-use seeding,
// default selection and archival so a company always has a selectable default.
export async function ensureDefaultQuoteTemplate(db, req) {
  if (!req.companyId) fail('company_required', 'Select a company to configure quote templates.', 403);
  await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`quote-default:${req.companyId}`]);
  const settings = (await db.query('SELECT * FROM agreement_settings WHERE company_id=$1', [req.companyId])).rows[0];
  if (settings?.default_template_id) {
    const current = (await db.query('SELECT * FROM agreement_templates WHERE company_id=$1 AND template_id=$2 AND archived_at IS NULL ORDER BY version DESC LIMIT 1', [req.companyId, settings.default_template_id])).rows[0];
    if (current) return { ...current, content: completeTemplateContent(current.content), is_default: true };
  }
  let template = (await db.query('SELECT * FROM agreement_templates WHERE company_id=$1 AND archived_at IS NULL ORDER BY created_at,template_id,version DESC LIMIT 1', [req.companyId])).rows[0];
  if (template) template = (await db.query('SELECT * FROM agreement_templates WHERE template_id=$1 AND company_id=$2 AND archived_at IS NULL ORDER BY version DESC LIMIT 1', [template.template_id, req.companyId])).rows[0];
  else {
    const content = completeTemplateContent(settings?.content || {});
    if (!content.consent_text.trim()) content.consent_text = 'I agree to this quote and its displayed agreement and terms, and consent to signing electronically.';
    template = (await db.query('INSERT INTO agreement_templates(template_id,version,company_id,name,content,created_by) VALUES($1,1,$2,$3,$4::jsonb,$5) RETURNING *', [randomUUID(), req.companyId, 'Default Quote', JSON.stringify(content), req.userId])).rows[0];
  }
  await db.query('INSERT INTO agreement_settings(company_id,default_template_id) VALUES($1,$2) ON CONFLICT(company_id) DO UPDATE SET default_template_id=EXCLUDED.default_template_id,updated_at=now()', [req.companyId, template.template_id]);
  return { ...template, content: completeTemplateContent(template.content), is_default: true };
}

export async function listQuoteTemplates(pool, req) {
  return quoteTemplateTransaction(pool, async db => {
    const fallback = await ensureDefaultQuoteTemplate(db, req);
    const rows = (await db.query('SELECT DISTINCT ON(template_id) template_id,version,name,content,created_at FROM agreement_templates WHERE company_id=$1 AND archived_at IS NULL ORDER BY template_id,version DESC', [req.companyId])).rows;
    return rows.map(row => ({ ...row, content: completeTemplateContent(row.content), is_default: row.template_id === fallback.template_id }));
  });
}

export async function resolveQuoteTemplateOptions(pool, req, raw = {}, { previous = null } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('quote_options_invalid', 'Quote options must be an object.');
  // Personal legacy records without a company cannot issue public agreements.
  if (!req.companyId) return normalizeQuoteOptions(raw);
  return quoteTemplateTransaction(pool, async db => {
    const fallback = await ensureDefaultQuoteTemplate(db, req);
    const explicit = Object.hasOwn(raw, 'template') && raw.template != null;
    const selection = explicit ? raw.template : previous?.template;
    let source = fallback;
    if (selection) {
      if (!validID(selection.id) || !Number.isSafeInteger(selection.version) || selection.version < 1) fail('quote_template_invalid', 'Select a valid quote template version.');
      source = (await db.query('SELECT * FROM agreement_templates WHERE company_id=$1 AND template_id=$2 AND version=$3', [req.companyId, selection.id, selection.version])).rows[0];
      if (!source || (source.archived_at && previous?.template?.id !== source.template_id)) fail('agreement_template_missing', 'This template is unavailable. Select another template.', 404);
    }
    const original = completeTemplateContent(source.content);
    const content = completeTemplateContent(selection?.content ?? original);
    // An older client can still change commercial options. Incorporate only its
    // explicitly submitted keys into the saved override; new clients send the template.
    if (!explicit) {
      const legacy = Object.fromEntries(QUOTE_TEMPLATE_OPTION_KEYS.filter(key => Object.hasOwn(raw, key)).map(key => [key, raw[key]]));
      content.quote_defaults = normalizeQuoteTemplateDefaults({ ...content.quote_defaults, ...legacy });
      content.booking_preference = content.quote_defaults.allow_customer_booking;
      content.plan_offer_preference = content.quote_defaults.offer_service_plans;
    }
    const options = normalizeQuoteOptions({ ...previous, ...raw, ...content.quote_defaults,
      optional_addons: [], billing_address: '', public_notes: '', scope_exclusions: '',
      template: { id: source.template_id, version: source.version, name: source.name, content,
        is_customized: quoteContentHash(content) !== quoteContentHash(original) },
    });
    return options;
  });
}
