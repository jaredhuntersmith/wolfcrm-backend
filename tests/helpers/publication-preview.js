// Fixtures emulate the staff client's exact-preview step. The workflow acceptance
// suite intentionally does not use this helper and tests missing/stale hash rejection.
export function previewPublications(service) {
  const publish = service.publish.bind(service), hashes = new Map();
  service.publish = async (req, quoteID, raw, options = {}) => {
    if (!options.preview && raw.expected_preview_hash === undefined) {
      const key = `${req.companyId}:${raw.request_id}`;
      let hash = hashes.get(key);
      if (!hash) {
        const preview = await publish(req, quoteID, raw, { preview: true });
        hash = preview.preview_hash; hashes.set(key, hash);
      }
      raw = { ...raw, expected_preview_hash: hash };
    }
    return publish(req, quoteID, raw, options);
  };
}
