export async function installFinanceSystem({ app, pool, authRequired, requireEmployer }) {
  if (!app || !pool || !authRequired || !requireEmployer) {
    throw new Error("finance_installer_missing_dependencies");
  }

  // Finance is intentionally shell-only in this pass. Future finance routes,
  // schema setup, deterministic calculations, and provider integrations should
  // live here instead of growing Backend/index.js.
  app.get("/api/finance/health", authRequired, requireEmployer, async (req, res) => {
    if (!req.companyId) {
      return res.status(400).json({ error: "company_required" });
    }
    res.json({
      ok: true,
      company_id: req.companyId,
      setup_complete: false
    });
  });
}
