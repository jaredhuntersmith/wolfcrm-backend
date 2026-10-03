import { QuoteContractError } from './quote-contract-domain.js';
import { normalizeFooterLinks } from './agreement-presentation.js';

export async function installCompanyFooterSchema(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS company_agreement_footers (
    company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE RESTRICT,
    links JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
}

// Separate from immutable agreement content. First access preserves previously
// configured links; later template edits cannot change these company settings.
export async function companyFooter(db, companyId) {
  const existing = (await db.query('SELECT links,version FROM company_agreement_footers WHERE company_id=$1', [companyId])).rows[0];
  if (existing) return existing;
  const sources = (await db.query(`
    WITH current_templates AS (
      SELECT DISTINCT ON(template_id) * FROM agreement_templates
      WHERE company_id=$1 ORDER BY template_id,version DESC
    ), candidates AS (
      SELECT t.content->'customer_page'->'footer_links' AS links,0 AS priority,t.created_at AS stamp
      FROM current_templates t JOIN agreement_settings s ON s.company_id=t.company_id AND s.default_template_id=t.template_id
      WHERE t.archived_at IS NULL
      UNION ALL SELECT content->'customer_page'->'footer_links',1,updated_at FROM agreement_settings WHERE company_id=$1
      UNION ALL SELECT content->'customer_page'->'footer_links',2,created_at FROM current_templates WHERE archived_at IS NULL
      UNION ALL (SELECT snapshot->'customer_page'->'footer_links',3,created_at FROM quote_agreements WHERE company_id=$1 ORDER BY created_at DESC LIMIT 1)
    ) SELECT links FROM candidates ORDER BY priority,stamp DESC`, [companyId])).rows;
  const links = normalizeFooterLinks({});
  for (const source of sources) for (const key of Object.keys(links)) {
    if (links[key] || !source.links?.[key]) continue;
    try { links[key] = normalizeFooterLinks({ [key]: source.links[key] })[key]; }
    catch { /* Invalid legacy values must not break an otherwise valid customer link. */ }
  }
  await db.query('INSERT INTO company_agreement_footers(company_id,links) VALUES($1,$2::jsonb) ON CONFLICT(company_id) DO NOTHING', [companyId, JSON.stringify(links)]);
  return (await db.query('SELECT links,version FROM company_agreement_footers WHERE company_id=$1', [companyId])).rows[0];
}

export function installCompanyFooterRoutes({ app, pool, staff, wrap }) {
  app.get('/api/agreements/footer', ...staff('quotes.view'), wrap(async (req, res) => {
    res.json(await companyFooter(pool, req.companyId));
  }));
  app.put('/api/agreements/footer', ...staff('settings.manage_company'), wrap(async (req, res) => {
    const links = normalizeFooterLinks(req.body.links);
    if (!Number.isInteger(req.body.expected_version) || req.body.expected_version < 1)
      throw new QuoteContractError('footer_version_required', 'Reload the company links before saving.', 409);
    await companyFooter(pool, req.companyId);
    const saved = (await pool.query(`UPDATE company_agreement_footers SET links=$2::jsonb,version=version+1,updated_at=now()
      WHERE company_id=$1 AND version=$3 RETURNING links,version`, [req.companyId, JSON.stringify(links), req.body.expected_version])).rows[0];
    if (!saved) throw new QuoteContractError('footer_changed', 'Company links changed on another device. Reload before saving.', 409);
    res.json(saved);
  }));
}
