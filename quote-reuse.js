import { validateCatalog } from './quote-calculator/domain.js';

const emptyCatalog = () => ({ questions: [], components: [], services: [], quote_minimum_cents: null });

/** Restore missing historical definitions without replacing current company rules. */
export function mergeHistoricalQuoteCatalog(current = emptyCatalog(), frozen = emptyCatalog(), selectedServiceIDs = []) {
  const selected = new Set(selectedServiceIDs);
  const merged = structuredClone(current);
  let restored = 0;
  for (const [key, identity] of [['questions', 'id'], ['components', 'id'], ['services', 'service_id']]) {
    merged[key] ??= [];
    const existing = new Set(merged[key].map(value => value[identity]));
    for (const value of frozen[key] || []) {
      const related = key === 'services' ? selected.has(value.service_id) : value.service_ids?.some(id => selected.has(id));
      if (!related || existing.has(value[identity])) continue;
      const copy = structuredClone(value);
      if (key !== 'services') copy.service_ids = copy.service_ids.filter(id => selected.has(id));
      merged[key].push(copy);
      existing.add(copy[identity]);
      restored++;
    }
  }
  if (restored) validateCatalog(merged);
  return { config: merged, restored };
}
