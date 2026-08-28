import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  normalizeWebsitePageCreate,
  normalizeWebsitePageReorder,
  normalizeWebsitePageUpdate,
  normalizeWebsiteProjectCreate,
  normalizeWebsiteProjectUpdate,
  normalizeWebsiteSlug,
  starterPageForProject,
} from "../website-builder.js";

const source = readFileSync(new URL("../website-builder.js", import.meta.url), "utf8");
const indexSource = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("project kinds create the correct safe starter page", () => {
  const website = normalizeWebsiteProjectCreate({ name: "  Acme Services  ", kind: "website" });
  assert.deepEqual(website, { name: "Acme Services", kind: "website" });
  assert.equal(starterPageForProject({ kind: website.kind, projectName: website.name }).slug, "/");
  assert.equal(starterPageForProject({ kind: "landing_page", projectName: "Summer" }).page_kind, "landing");
  const funnel = starterPageForProject({ kind: "funnel", projectName: "Estimate flow" });
  assert.equal(funnel.name, "Step 1");
  assert.equal(funnel.slug, "/step-1");
  assert.equal(funnel.page_kind, "funnel_step");
  assert.equal(funnel.content.schema_version, 1);
  assert.equal(funnel.content.blocks[0].type, "hero");
  assert.equal("script" in funnel.content.blocks[0], false);
  assert.throws(
    () => normalizeWebsiteProjectCreate({ name: "Bad", kind: "store" }),
    /Website, Landing Page, or Funnel/,
  );
});

test("page paths normalize to bounded relative slugs", () => {
  assert.equal(normalizeWebsiteSlug("/Roofing/Free Estimate/"), "/roofing/free-estimate");
  assert.equal(normalizeWebsiteSlug("", "Storm Repair"), "/storm-repair");
  assert.equal(normalizeWebsiteSlug("/"), "/");
  assert.throws(() => normalizeWebsiteSlug("https://outside.example/page"), /path such as/);
  assert.throws(() => normalizeWebsiteSlug("/estimate?company=other"), /path such as/);
});

test("project and page writes require optimistic versions and bounded mutations", () => {
  assert.deepEqual(
    normalizeWebsiteProjectUpdate({ expected_version: 4, lifecycle_status: "archived" }),
    { expected_version: 4, name: undefined, lifecycle_status: "archived" },
  );
  const page = normalizeWebsitePageCreate(
    { name: "Service Area", slug: "service-area", expected_project_version: "3" },
    "website",
  );
  assert.equal(page.slug, "/service-area");
  assert.equal(page.expected_project_version, 3);
  assert.deepEqual(normalizeWebsitePageReorder({ target_index: "2", expected_project_version: 5 }), {
    target_index: 2,
    expected_project_version: 5,
  });
  assert.throws(() => normalizeWebsiteProjectUpdate({ expected_version: 1 }), /Change the project/);
  assert.throws(
    () => normalizeWebsitePageUpdate({ expected_version: 2, expected_project_version: 3, is_home: "yes" }),
    /must be true or false/,
  );
});

test("schema enforces company/project integrity and recoverable active-page invariants", () => {
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_projects/);
  assert.match(source, /FOREIGN KEY\(project_id, company_id\) REFERENCES website_projects\(id, company_id\) ON DELETE CASCADE/);
  assert.match(source, /website_pages_active_slug_uidx[\s\S]*WHERE archived_at IS NULL/);
  assert.match(source, /website_pages_active_home_uidx[\s\S]*WHERE is_home AND archived_at IS NULL/);
  assert.match(source, /website_last_page_required/);
  assert.doesNotMatch(source, /app\.delete\("\/api\/website-builder/);
});

test("routes keep authentication, capabilities, and company scope authoritative", () => {
  assert.match(indexSource, /requireView: requireCapability\("website\.view"\)/);
  assert.match(indexSource, /requireManage: requireCapability\("website\.manage"\)/);
  assert.match(source, /app\.get\("\/api\/website-builder\/projects", authRequired, requireView/);
  assert.match(source, /app\.post\("\/api\/website-builder\/projects", authRequired, requireManage/);
  assert.match(source, /app\.patch\("\/api\/website-builder\/projects\/:projectId\/pages\/:pageId", authRequired, requireManage/);
  assert.match(source, /WHERE id::text = \$1 AND company_id = \$2/);
  assert.match(source, /WHERE id::text = \$1 AND project_id::text = \$2 AND company_id = \$3/);
});
