import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  flattenWebsiteBlocks,
  normalizeWebsitePageCreate,
  normalizeWebsitePageChrome,
  normalizeWebsitePageDuplicate,
  normalizeWebsitePageContent,
  normalizeWebsitePageReorder,
  normalizeWebsitePageSeo,
  normalizeWebsitePageUpdate,
  normalizeWebsiteMediaReserve,
  normalizeWebsiteMediaUpdate,
  normalizeWebsiteProjectCreate,
  normalizeWebsiteProjectNavigation,
  normalizeWebsiteProjectTheme,
  normalizeWebsiteProjectUpdate,
  normalizeWebsitePublishingSettings,
  normalizeWebsiteDomainHostname,
  normalizeWebsiteDomainSettings,
  normalizeWebsiteDomainVerification,
  normalizeWebsitePublish,
  normalizeWebsiteFormCreate,
  normalizeWebsiteFormUpdate,
  normalizeWebsiteFormSubmission,
  normalizeWebsiteAnalyticsEvent,
  normalizeWebsiteAnalyticsReportQuery,
  normalizeWebsiteSubdomain,
  normalizeWebsiteSectionCreate,
  normalizeWebsiteSectionUpdate,
  normalizeWebsiteSlug,
  starterPageForProject,
  websiteTemplatesForKind,
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
    { expected_version: 4, name: undefined, lifecycle_status: "archived", theme: undefined, navigation: undefined },
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

test("project navigation is bounded, page-linked, and data-only", () => {
  const pageId = "123e4567-e89b-42d3-a456-426614174000";
  const navigation = normalizeWebsiteProjectNavigation({
    mode: "custom",
    show_brand: false,
    cta_label: "Get an estimate",
    cta_href: "/contact",
    items: [{ page_id: pageId, label: "Roofing" }],
    footer_text: "Serving the metro since 1998.",
    show_powered_by: false,
    header_content: { schema_version: 1, blocks: [{ id: "223e4567-e89b-42d3-a456-426614174000", type: "text", data: { heading: "Free estimates", body: "Book today", alignment: "center" } }] },
    footer_content: { schema_version: 1, blocks: [] },
  });
  assert.equal(navigation.items[0].page_id, pageId);
  assert.equal(navigation.show_brand, false);
  assert.equal(navigation.footer_text, "Serving the metro since 1998.");
  assert.equal(navigation.show_powered_by, false);
  assert.equal(navigation.header_content.blocks[0].type, "text");
  assert.deepEqual(
    normalizeWebsiteProjectUpdate({ expected_version: 3, navigation }).navigation,
    navigation,
  );
  assert.throws(() => normalizeWebsiteProjectNavigation({ ...navigation, cta_href: "javascript:alert(1)" }), /local path/);
  assert.throws(() => normalizeWebsiteProjectNavigation({ ...navigation, script: "alert(1)" }), /unsupported script/);
  assert.throws(() => normalizeWebsiteProjectNavigation({ ...navigation, items: [...navigation.items, navigation.items[0]] }), /only once/);
  assert.throws(() => normalizeWebsiteProjectNavigation({ ...navigation, footer_text: "x".repeat(241) }), /at most 240/);
  assert.throws(() => normalizeWebsiteProjectNavigation({ ...navigation, show_powered_by: "no" }), /must be true or false/);
});

test("page duplication and chrome overrides stay optimistic and structured", () => {
  assert.deepEqual(normalizeWebsitePageDuplicate({ expected_version: "2", expected_project_version: 4 }), { expected_version: 2, expected_project_version: 4 });
  const chrome = normalizeWebsitePageChrome({
    header_mode: "replace",
    footer_mode: "hidden",
    header_content: { schema_version: 1, blocks: [{ id: "323e4567-e89b-42d3-a456-426614174000", type: "button", data: { label: "Call", href: "tel:+15551234567", alignment: "left", style: "primary" } }] },
    footer_content: { schema_version: 1, blocks: [] },
  });
  assert.equal(chrome.header_mode, "replace");
  assert.equal(chrome.footer_mode, "hidden");
  assert.throws(() => normalizeWebsitePageChrome({ ...chrome, header_mode: "custom" }), /inherit, hide, or replace/);
  assert.throws(() => normalizeWebsitePageChrome({ ...chrome, header_content: { schema_version: 1, blocks: [{ id: "423e4567-e89b-42d3-a456-426614174000", type: "form", data: { form_id: "523e4567-e89b-42d3-a456-426614174000", heading: "Lead", body: "", button_label: "Send" } }] } }), /Text, Callout, or Button/);
  assert.match(source, /pages\/:pageId\/duplicate/);
  assert.match(source, /action: "page\.duplicated"/);
});

test("global project themes are complete, bounded data-only tokens", () => {
  const theme = normalizeWebsiteProjectTheme({
    primary_color: "#0F766E",
    heading_font: "classic",
    corner_style: "soft",
    heading_scale: "display",
    body_scale: "large",
    content_width: "wide",
    section_spacing: "spacious",
    button_style: "outline",
  });
  assert.equal(theme.primary_color, "#0f766e");
  assert.equal(theme.heading_font, "classic");
  assert.equal(theme.body_font, "system");
  assert.equal(theme.background_color, "#f8fafc");
  assert.equal(theme.heading_scale, "display");
  assert.equal(theme.body_scale, "large");
  assert.equal(theme.content_width, "wide");
  assert.equal(theme.section_spacing, "spacious");
  assert.equal(theme.button_style, "outline");
  assert.deepEqual(
    normalizeWebsiteProjectUpdate({ expected_version: 3, theme }).theme,
    theme,
  );
  assert.throws(() => normalizeWebsiteProjectTheme({ primary_color: "red" }), /six-digit hex/);
  assert.throws(() => normalizeWebsiteProjectTheme({ heading_font: "remote-font" }), /unsupported/);
  assert.throws(() => normalizeWebsiteProjectTheme({ content_width: "100vw" }), /unsupported/);
  assert.throws(() => normalizeWebsiteProjectTheme({ script: "alert(1)" }), /unsupported script/);
});

test("structured page content accepts only bounded data-only blocks", () => {
  const id = "123e4567-e89b-42d3-a456-426614174000";
  const content = normalizeWebsitePageContent({
    schema_version: 1,
    blocks: [
      {
        id,
        type: "hero",
        data: {
          heading: "Storm repair",
          body: "Fast local help.",
          button_label: "Call now",
          button_href: "tel:+15551234567",
          alignment: "center",
        },
      },
    ],
  });
  assert.equal(content.blocks[0].data.button_href, "tel:+15551234567");
  assert.deepEqual(
    normalizeWebsitePageUpdate({ expected_version: 2, expected_project_version: 3, content }).content,
    content,
  );
  assert.throws(
    () => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "html", data: { html: "<script />" } }] }),
    /unsupported type/,
  );
  assert.throws(
    () => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "hero", data: { heading: "Bad", body: "", button_label: "Go", button_href: "javascript:alert(1)" } }] }),
    /Button links must use/,
  );
  assert.throws(
    () => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "spacer", data: {} }, { id, type: "spacer", data: {} }] }),
    /unique identifier/,
  );
});

test("selected-node design controls are sparse bounded tokens", () => {
  const id = "123e4567-e89b-42d3-a456-426614174099";
  const content = normalizeWebsitePageContent({
    schema_version: 1,
    blocks: [{
      id,
      type: "hero",
      data: { heading: "Designed service", body: "Safe tokens", button_label: "Book", button_href: "/book" },
      design: { font_family: "heading", font_size: "3xl", padding: "xl", background: "primary", text_color: "inverse", radius: "rounded", shadow: "medium", hover_effect: "lift", button_style: "outline", button_size: "large", button_width: "full", opacity: "opaque", margin: "inherit" },
    }],
  });
  assert.deepEqual(content.blocks[0].design, { font_family: "heading", font_size: "3xl", text_color: "inverse", padding: "xl", background: "primary", radius: "rounded", shadow: "medium", opacity: "opaque", hover_effect: "lift", button_style: "outline", button_size: "large", button_width: "full" });
  assert.equal("margin" in content.blocks[0].design, false);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, design: { background: "url(https://evil.example)" } }] }), /background design setting is invalid/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, design: { hover_effect: "spin(360deg)" } }] }), /hover effect design setting is invalid/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, design: { css: "display:none" } }] }), /unsupported css field/);
});

test("responsive block overrides are sparse, inherited, and bounded", () => {
  const id = "123e4567-e89b-42d3-a456-426614174096";
  const content = normalizeWebsitePageContent({ schema_version: 1, blocks: [{
    id,
    type: "grid",
    data: { columns: 3, gap: "large", stack_at: "mobile" },
    children: [],
    responsive: {
      desktop: { design: { max_width: "wide", font_size: "inherit" }, order: 2 },
      tablet: { design: { font_size: "lg", background: "surface" }, layout: { columns: 2, gap: "medium", alignment: "inherit" } },
      mobile: { design: { font_size: "base", padding: "sm", shadow: "soft", hover_effect: "grow" }, layout: { columns: 1, padding: "small" }, visibility: "hidden", order: -2 },
    },
  }] });
  assert.deepEqual(content.blocks[0].responsive.desktop, { design: { max_width: "wide" }, order: 2 });
  assert.deepEqual(content.blocks[0].responsive.tablet.layout, { columns: 2, gap: "medium" });
  assert.equal(content.blocks[0].responsive.mobile.visibility, "hidden");
  assert.equal(content.blocks[0].responsive.mobile.design.hover_effect, "grow");
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, responsive: { watch: { visibility: "hidden" } } }] }), /unsupported watch field/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, responsive: { mobile: { design: { css: "display:none" } } } }] }), /unsupported css field/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, responsive: { tablet: { order: 21 } } }] }), /whole number/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: {}, responsive: { mobile: { layout: { columns: 0 } } } }] }), /one through six/);
});

test("inline rich text is canonical bounded data without stored HTML", () => {
  const id = "123e4567-e89b-42d3-a456-426614174098";
  const content = normalizeWebsitePageContent({ schema_version: 1, blocks: [{
    id, type: "text", data: { heading: "Structured", body: "stale", alignment: "left", body_rich_text: { version: 1, spans: [
      { text: "Trusted ", marks: ["italic", "bold"] },
      { text: "team", marks: ["bold", "italic"], link: "/contact" },
      { text: " today.", marks: ["underline", "strikethrough"] },
    ] } },
  }] });
  assert.equal(content.blocks[0].data.body, "Trusted team today.");
  assert.deepEqual(content.blocks[0].data.body_rich_text.spans[0].marks, ["bold", "italic"]);
  assert.equal(content.blocks[0].data.body_rich_text.spans[1].link, "/contact");
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: { body_rich_text: { version: 1, spans: [{ text: "Bad", link: "javascript:alert(1)" }] } } }] }), /Button links must use/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: { body_rich_text: { version: 1, spans: [{ text: "Bad", marks: ["script"] }] } } }] }), /unsupported mark/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id, type: "text", data: { body_rich_text: { version: 1, spans: [{ text: "Bad", html: "<b>Bad</b>" }] } } }] }), /unsupported html/);
});

test("structured layout nodes are recursively bounded", () => {
  const id = (suffix) => `123e4567-e89b-42d3-a456-4266141740${suffix}`;
  const content = normalizeWebsitePageContent({ schema_version: 1, blocks: [{
    id: id("10"), type: "section", data: { width: "boxed", padding: "large", background: "surface", overlay: 10 }, children: [{
      id: id("11"), type: "row", data: { columns: 2, gap: "medium", stack_at: "mobile", alignment: "stretch" }, children: [
        { id: id("12"), type: "column", data: { alignment: "stretch", padding: "small" }, children: [{ id: id("13"), type: "text", data: { heading: "Local service", body: "Fast help", alignment: "left" } }] },
        { id: id("14"), type: "column", data: { alignment: "center", padding: "small" }, children: [{ id: id("15"), type: "divider", data: { style: "dashed", width: "medium", tone: "primary" } }] },
      ],
    }],
  }] });
  assert.equal(flattenWebsiteBlocks(content).length, 6);
  assert.equal(content.blocks[0].children[0].data.columns, 2);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("20"), type: "row", data: { columns: 2 }, children: [] }] }), /matching the configured column count/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("21"), type: "section", data: {}, children: [{ id: id("21"), type: "text", data: {} }] }] }), /unique identifier/);
});

test("professional element catalog normalizes safe marketing CRM navigation and funnel blocks", () => {
  const id = (suffix) => `123e4567-e89b-42d3-a456-4266141750${suffix}`;
  const content = normalizeWebsitePageContent({ schema_version: 1, blocks: [
    { id: id("00"), type: "button", data: { label: "Book now", href: "/book", alignment: "center", style: "secondary" } },
    { id: id("01"), type: "testimonials", data: { heading: "Reviews", items: ["Excellent — Sam"], columns: 1 } },
    { id: id("02"), type: "stats", data: { heading: "Results", items: ["500+ projects"], columns: 2 } },
    { id: id("03"), type: "services", data: { heading: "Services", items: ["Repairs"], columns: 3 } },
    { id: id("04"), type: "contact_details", data: { heading: "Contact", phone: "555-555-1212", email: "team@example.com", address: "Austin", hours: "Weekdays" } },
    { id: id("05"), type: "link_list", data: { heading: "Explore", items: ["Services|/services", "Call|tel:+15555551212"], columns: 2 } },
    { id: id("06"), type: "step_indicator", data: { heading: "Progress", items: ["Details", "Schedule"], active_step: 2 } },
    { id: id("07"), type: "urgency_banner", data: { heading: "Limited times", body: "Book today", button_label: "Check", button_href: "/book", alignment: "center" } },
  ] });
  assert.equal(content.blocks.length, 8);
  assert.equal(content.blocks[5].data.items[1], "Call|tel:+15555551212");
  assert.equal(content.blocks[6].data.active_step, 2);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("08"), type: "link_list", data: { heading: "Unsafe", items: ["Bad|javascript:alert(1)"], columns: 1 } }] }), /Button links must use/);
});

test("advanced disclosure, video, social links, maps, galleries, and announcements remain bounded data-only content", () => {
  const id = (suffix) => `223e4567-e89b-42d3-a456-4266141750${suffix}`;
  const content = normalizeWebsitePageContent({ schema_version: 1, blocks: [
    { id: id("00"), type: "accordion", data: { heading: "FAQ", items: ["Do you offer estimates?|Yes, contact our team for the next available appointment."], active_item: 1 } },
    { id: id("01"), type: "tabs", data: { heading: "Services", items: ["Repair|Responsive repair service.", "Install|Careful installation service."], active_item: 2 } },
    { id: id("02"), type: "video", data: { heading: "Our process", provider: "youtube", video_id: "M7lc1UVf-VE", caption: "A short overview.", aspect_ratio: "widescreen" } },
    { id: id("03"), type: "social_links", data: { heading: "Follow us", items: ["Instagram|https://www.instagram.com/wolfcrm", "x|https://twitter.com/wolfcrm"], alignment: "center" } },
    { id: id("11"), type: "map", data: { heading: "Find us", address: "100 Main St, Austin, TX", zoom: 15, height: "tall", link_label: "Directions" } },
    { id: id("15"), type: "gallery", data: { heading: "Recent work", items: [`${id("20")}|Installed system beside a brick home`, `${id("21")}|Technician completing a service visit`], columns: 3, aspect_ratio: "landscape", gap: "compact" } },
    { id: id("22"), type: "announcement_bar", data: { message: "Storm response appointments are open.", link_label: "Book now", link_href: "/contact", tone: "accent", alignment: "left", behavior: "dismissible" } },
  ] });
  assert.equal(content.blocks[0].data.items[0], "Do you offer estimates?|Yes, contact our team for the next available appointment.");
  assert.equal(content.blocks[1].data.active_item, 2);
  assert.equal(content.blocks[2].data.video_id, "M7lc1UVf-VE");
  assert.equal(content.blocks[3].data.items[0], "instagram|https://www.instagram.com/wolfcrm");
  assert.deepEqual(content.blocks[4].data, { heading: "Find us", address: "100 Main St, Austin, TX", zoom: 15, height: "tall", link_label: "Directions" });
  assert.deepEqual(content.blocks[5].data, { heading: "Recent work", items: [`${id("20")}|Installed system beside a brick home`, `${id("21")}|Technician completing a service visit`], columns: 3, aspect_ratio: "landscape", gap: "compact" });
  assert.deepEqual(content.blocks[6].data, { message: "Storm response appointments are open.", link_label: "Book now", link_href: "/contact", tone: "accent", alignment: "left", behavior: "dismissible" });
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("04"), type: "accordion", data: { items: ["Missing separator"], active_item: 1 } }] }), /Label\|Content/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("05"), type: "tabs", data: { items: ["One|Only"], active_item: 2 } }] }), /existing item/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("06"), type: "video", data: { provider: "youtube", video_id: "https:\/\/youtube.com\/watch?v=bad", embed: "<iframe>" } }] }), /unsupported embed/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("07"), type: "video", data: { provider: "remote", video_id: "abcdef" } }] }), /Video provider/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("08"), type: "social_links", data: { items: ["facebook|https://evil.example/wolfcrm"] } }] }), /platform HTTPS hostname/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("09"), type: "social_links", data: { items: ["instagram|http://instagram.com/wolfcrm"] } }] }), /platform HTTPS hostname/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("10"), type: "social_links", data: { items: ["facebook|https://facebook.com:443/wolfcrm"] } }] }), /platform HTTPS hostname/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("12"), type: "map", data: { address: "", zoom: 14 } }] }), /require a public address/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("13"), type: "map", data: { address: "Austin, TX", zoom: 21 } }] }), /zoom/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("14"), type: "map", data: { address: "Austin, TX", zoom: 14, provider_url: "https://evil.example" } }] }), /unsupported provider_url/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("16"), type: "gallery", data: { items: ["https://evil.example/image.jpg|Unsafe"], columns: 3 } }] }), /valid company media/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("17"), type: "gallery", data: { items: [`${id("20")}|One`, `${id("20")}|Duplicate`], columns: 3 } }] }), /must be unique/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("18"), type: "gallery", data: { items: [], columns: 5 } }] }), /columns/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("19"), type: "gallery", data: { items: [], columns: 3, script: "alert(1)" } }] }), /unsupported script/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("23"), type: "announcement_bar", data: { message: "Book now", link_label: "Book", link_href: "javascript:alert(1)" } }] }), /Button links must use/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("24"), type: "announcement_bar", data: { message: "Book now", link_label: "Book", link_href: "" } }] }), /provided together/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("25"), type: "announcement_bar", data: { message: "Book now", behavior: "sticky-script" } }] }), /Announcement behavior/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: id("26"), type: "announcement_bar", data: { message: "Book now", script: "alert(1)" } }] }), /unsupported script/);
});

test("page SEO and social metadata is bounded and data-only", () => {
  const seo = normalizeWebsitePageSeo({
    title: "  Roof repair in Austin  ",
    description: "Fast local roof repair.",
    social_title: "Storm damage help",
    social_description: "Book a local inspection.",
    hide_from_search: true,
  });
  assert.equal(seo.title, "Roof repair in Austin");
  assert.equal(seo.hide_from_search, true);
  assert.deepEqual(
    normalizeWebsitePageUpdate({ expected_version: 2, expected_project_version: 3, seo }).seo,
    seo,
  );
  assert.throws(() => normalizeWebsitePageSeo({ title: "x".repeat(71) }), /at most 70/);
  assert.throws(() => normalizeWebsitePageSeo({ title: "Okay", script: "alert(1)" }), /unsupported script/);
  assert.throws(() => normalizeWebsitePageSeo({ hide_from_search: "yes" }), /true or false/);
});

test("templates and reusable sections stay structured, bounded, and versioned", () => {
  const templates = websiteTemplatesForKind("landing_page");
  assert.ok(templates.length >= 2);
  assert.ok(templates.every((template) => template.kinds.includes("landing_page")));
  assert.ok(templates.every((template) => template.content.blocks.length >= 6));
  assert.ok(templates.every((template) => template.content.blocks.every((block) => block.type === "section")));
  const allTemplateBlocks = templates.flatMap((template) => flattenWebsiteBlocks(template.content));
  assert.ok(allTemplateBlocks.length >= 40);
  assert.equal(new Set(allTemplateBlocks.map((block) => block.id)).size, allTemplateBlocks.length);
  assert.ok(allTemplateBlocks.some((block) => block.type === "row"));
  assert.ok(allTemplateBlocks.some((block) => block.type === "testimonials"));
  const quoteFunnel = websiteTemplatesForKind("funnel");
  assert.equal(quoteFunnel.length, 1);
  assert.ok(flattenWebsiteBlocks(quoteFunnel[0].content).some((block) => block.type === "step_indicator"));
  assert.ok(flattenWebsiteBlocks(quoteFunnel[0].content).some((block) => block.type === "services"));
  const content = { schema_version: 1, blocks: [templates[0].content.blocks[0]] };
  assert.deepEqual(normalizeWebsiteSectionCreate({ name: " Hero CTA ", content }), { name: "Hero CTA", content });
  assert.deepEqual(normalizeWebsiteSectionUpdate({ expected_version: 2, lifecycle_status: "archived" }), {
    expected_version: 2,
    name: undefined,
    content: undefined,
    lifecycle_status: "archived",
  });
  assert.throws(() => normalizeWebsiteSectionCreate({ name: "Empty", content: { schema_version: 1, blocks: [] } }), /at least one block/);
  assert.throws(() => websiteTemplatesForKind("store"), /Website, Landing Page, or Funnel/);
});

test("website media reservations and image blocks are bounded and data-only", () => {
  const mediaId = "123e4567-e89b-42d3-a456-426614174099";
  assert.deepEqual(normalizeWebsiteMediaReserve({
    file_name: " Crew <photo>.webp ",
    mime_type: "image/webp",
    byte_size: 2048,
    alt_text: "Crew installing a roof",
  }), {
    file_name: "Crew _photo_.webp",
    mime_type: "image/webp",
    byte_size: 2048,
    alt_text: "Crew installing a roof",
  });
  assert.deepEqual(normalizeWebsiteMediaUpdate({ expected_version: 2, lifecycle_status: "archived" }), {
    expected_version: 2,
    alt_text: undefined,
    lifecycle_status: "archived",
  });
  const content = normalizeWebsitePageContent({ schema_version: 1, blocks: [{
    id: "123e4567-e89b-42d3-a456-426614174000",
    type: "image",
    data: { media_id: mediaId, alt_text: "A roof", caption: "Completed project", fit: "cover", focal_x: 25, focal_y: 70 },
  }] });
  assert.equal(content.blocks[0].data.media_id, mediaId);
  assert.equal(content.blocks[0].data.focal_x, 25);
  assert.equal(content.blocks[0].data.focal_y, 70);
  const legacy = normalizeWebsitePageContent({ schema_version: 1, blocks: [{
    id: "123e4567-e89b-42d3-a456-426614174001", type: "image", data: { media_id: mediaId, fit: "contain" },
  }] });
  assert.equal(legacy.blocks[0].data.focal_x, 50);
  assert.equal(legacy.blocks[0].data.focal_y, 50);
  assert.throws(() => normalizeWebsiteMediaReserve({ file_name: "x.svg", mime_type: "image/svg+xml", byte_size: 10 }), /JPEG, PNG, WebP, or GIF/);
  assert.throws(() => normalizeWebsiteMediaReserve({ file_name: "large.jpg", mime_type: "image/jpeg", byte_size: 10 * 1024 * 1024 + 1 }), /10 MB/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: "123e4567-e89b-42d3-a456-426614174000", type: "image", data: { media_id: mediaId, fit: "stretch" } }] }), /cover or contain/);
  assert.throws(() => normalizeWebsitePageContent({ schema_version: 1, blocks: [{ id: "123e4567-e89b-42d3-a456-426614174000", type: "image", data: { media_id: mediaId, focal_x: 101 } }] }), /whole percentages/);
});

test("publication settings require safe unique-style subdomains and optimistic versions", () => {
  assert.equal(normalizeWebsiteSubdomain(" Summer-Services "), "summer-services");
  assert.deepEqual(normalizeWebsitePublishingSettings({ expected_version: "4", subdomain: "summer-services" }), { expected_version: 4, subdomain: "summer-services" });
  assert.deepEqual(normalizeWebsitePublish({ expected_project_version: 7 }), { expected_project_version: 7 });
  assert.throws(() => normalizeWebsiteSubdomain("bad.example"), /lowercase letters/);
  assert.throws(() => normalizeWebsiteSubdomain("-bad"), /beginning and ending/);
});

test("custom domains normalize safe hostnames, canonical behavior, and versions", () => {
  assert.equal(normalizeWebsiteDomainHostname(" WWW.Example.COM. "), "www.example.com");
  assert.deepEqual(normalizeWebsiteDomainSettings({ expected_project_version: "8", hostname: "leads.example.com", canonical_mode: "primary" }), {
    expected_project_version: 8, hostname: "leads.example.com", canonical_mode: "primary",
  });
  assert.deepEqual(normalizeWebsiteDomainVerification({ expected_version: 2 }), { expected_version: 2 });
  assert.throws(() => normalizeWebsiteDomainHostname("https://example.com/path"), /valid custom hostname/);
  assert.throws(() => normalizeWebsiteDomainHostname("client.wolfcrm.site"), /outside wolfcrm.site/);
  assert.throws(() => normalizeWebsiteDomainHostname("127.0.0.1"), /valid custom hostname/);
});

test("CRM forms bound fields, CRM effects, optimistic updates, and public submissions", () => {
  const stageId = "123e4567-e89b-42d3-a456-426614174000";
  const form = normalizeWebsiteFormCreate({
    expected_project_version: 3,
    name: "Estimate request",
    fields: [
      { key: "full_name", label: "Name", type: "name", required: true },
      { key: "service", label: "Service", type: "select", required: true, options: ["Roofing", "Siding"] },
    ],
    settings: { contact_mode: "upsert", source: "Summer page", tags: ["lead", "campaign"], stage_id: stageId, task_title: "Call website lead", task_due_days: 1 },
  });
  assert.equal(form.expected_project_version, 3);
  assert.equal(form.settings.contact_mode, "upsert");
  assert.equal(form.fields[1].options.length, 2);
  assert.deepEqual(normalizeWebsiteFormUpdate({ expected_project_version: 4, expected_version: 2, lifecycle_status: "archived" }).lifecycle_status, "archived");
  assert.deepEqual(normalizeWebsiteFormSubmission({ idempotency_key: "submission_123456789", values: { full_name: "Avery" } }).values, { full_name: "Avery" });
  assert.throws(() => normalizeWebsiteFormCreate({ expected_project_version: 1, name: "Bad", fields: [{ key: "email", label: "Email", type: "email" }] }), /name field/);
  assert.throws(() => normalizeWebsiteFormSubmission({ idempotency_key: "short", values: {} }), /identifier/);
});

test("website analytics accepts only bounded first-party events and report ranges", () => {
  const event = normalizeWebsiteAnalyticsEvent({
    event_type: "cta_click",
    event_key: "123e4567-e89b-42d3-a456-426614174001",
    publication_id: "123e4567-e89b-42d3-a456-426614174002",
    page_id: "123e4567-e89b-42d3-a456-426614174003",
    block_id: "123e4567-e89b-42d3-a456-426614174004",
    visitor_token: "visitor_1234567890",
    attribution: { utm_source: "google", utm_campaign: "summer", referrer_host: "search.example" },
  });
  assert.equal(event.event_type, "cta_click");
  assert.equal(event.attribution.utm_source, "google");
  assert.deepEqual(normalizeWebsiteAnalyticsReportQuery({ days: "90" }), { days: 90 });
  assert.throws(() => normalizeWebsiteAnalyticsEvent({ ...event, event_type: "identify", email: "person@example.com" }), /unsupported/);
  assert.throws(() => normalizeWebsiteAnalyticsEvent({ ...event, attribution: { full_url: "https://example.com/private" } }), /unsupported field/);
  assert.throws(() => normalizeWebsiteAnalyticsReportQuery({ days: 31 }), /7, 30, 90, or 365/);
});

test("schema enforces company/project integrity and recoverable active-page invariants", () => {
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_projects/);
  assert.match(source, /ADD COLUMN IF NOT EXISTS theme JSONB NOT NULL/);
  assert.match(source, /ADD COLUMN IF NOT EXISTS navigation JSONB NOT NULL/);
  assert.match(source, /FOREIGN KEY\(project_id, company_id\) REFERENCES website_projects\(id, company_id\) ON DELETE CASCADE/);
  assert.match(source, /website_pages_active_slug_uidx[\s\S]*WHERE archived_at IS NULL/);
  assert.match(source, /website_pages_active_home_uidx[\s\S]*WHERE is_home AND archived_at IS NULL/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_sections/);
  assert.match(source, /website_sections_company_status_updated_idx/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_media/);
  assert.match(source, /website_media_company_status_updated_idx/);
  assert.match(source, /media_id UUID REFERENCES website_media/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_publications/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_domains/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_forms/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_form_submissions/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS website_analytics_events/);
  assert.match(source, /website_analytics_project_time_idx/);
  assert.match(source, /website_form_submissions_rate_idx/);
  assert.match(source, /website_domains_hostname_uidx/);
  assert.match(source, /UNIQUE\(project_id, version_number\)/);
  assert.match(source, /website_projects_subdomain_uidx/);
  assert.match(source, /website_last_page_required/);
  assert.doesNotMatch(source, /app\.delete\("\/api\/website-builder\/projects\/:projectId(?:\/pages\/|"\s*,)/);
});

test("routes keep authentication, capabilities, and company scope authoritative", () => {
  assert.match(indexSource, /requireView: requireCapability\("website\.view"\)/);
  assert.match(indexSource, /requireManage: requireCapability\("website\.manage"\)/);
  assert.match(indexSource, /requirePublish: requireCapability\("website\.publish"\)/);
  assert.match(source, /app\.get\("\/api\/public\/websites\/:subdomain"/);
  assert.match(source, /app\.get\("\/api\/public\/websites\/domain\/:hostname"/);
  assert.match(source, /app\.get\("\/api\/public\/websites\/domain-verification\/:hostname\/:token"/);
  assert.match(source, /app\.post\("\/api\/public\/website-forms\/:publicId\/submissions"/);
  assert.match(source, /app\.post\("\/api\/public\/website-analytics\/events"/);
  assert.match(source, /app\.get\("\/api\/website-builder\/projects\/:projectId\/analytics", authRequired, requireView/);
  assert.match(source, /app\.get\("\/api\/website-builder\/projects\/:projectId\/forms", authRequired, requireView/);
  assert.match(source, /app\.post\("\/api\/website-builder\/projects\/:projectId\/forms", authRequired, requireManage/);
  assert.match(source, /app\.patch\("\/api\/website-builder\/projects\/:projectId\/forms\/:formId", authRequired, requireManage/);
  assert.match(source, /lead\.received_website[\s\S]*lead\.external_form_received/);
  assert.match(source, /website_form_rate_limited/);
  assert.match(source, /https:\/\/\$\{row\.hostname\}\/\.well-known\/wolfcrm-domain-verification/);
  assert.match(source, /app\.put\("\/api\/website-builder\/projects\/:projectId\/domain", authRequired, requirePublish/);
  assert.match(source, /app\.post\("\/api\/website-builder\/projects\/:projectId\/domain\/verify", authRequired, requirePublish/);
  assert.match(source, /app\.get\("\/api\/website-builder\/projects\/:projectId\/publications", authRequired, requireView/);
  assert.match(source, /app\.post\("\/api\/website-builder\/projects\/:projectId\/publications", authRequired, requirePublish/);
  assert.match(source, /source_publication_id[\s\S]*publication\.rolled_back/);
  assert.match(source, /app\.get\("\/api\/website-builder\/projects", authRequired, requireView/);
  assert.match(source, /app\.post\("\/api\/website-builder\/projects", authRequired, requireManage/);
  assert.match(source, /app\.get\("\/api\/website-builder\/templates", authRequired, requireView/);
  assert.match(source, /app\.get\("\/api\/website-builder\/sections", authRequired, requireView/);
  assert.match(source, /app\.post\("\/api\/website-builder\/sections", authRequired, requireManage/);
  assert.match(source, /app\.patch\("\/api\/website-builder\/sections\/:sectionId", authRequired, requireManage/);
  assert.match(source, /app\.get\("\/api\/website-builder\/media", authRequired, requireView/);
  assert.match(source, /app\.post\("\/api\/website-builder\/media\/upload-url", authRequired, requireManage/);
  assert.match(source, /app\.post\("\/api\/website-builder\/media\/:mediaId\/complete", authRequired, requireManage/);
  assert.match(source, /app\.patch\("\/api\/website-builder\/media\/:mediaId", authRequired, requireManage/);
  assert.match(source, /input\.content !== undefined \|\| input\.lifecycle_status === "draft"[\s\S]*assertReadyMediaReferences\(client, req\.companyId, nextContent\)/);
  assert.match(source, /jsonb_path_exists\(p\.content[\s\S]*jsonb_path_exists\(s\.content/);
  assert.match(source, /Remove this image from active pages, Galleries, and reusable sections before retiring it/);
  assert.match(source, /app\.patch\("\/api\/website-builder\/projects\/:projectId\/pages\/:pageId", authRequired, requireManage/);
  assert.match(source, /const current = await loadPage[\s\S]*const nextContent = input\.content \?\? current\.content[\s\S]*content = \$8::jsonb/);
  assert.match(source, /const nextSeo = input\.seo \?\? current\.seo[\s\S]*seo = \$9::jsonb/);
  assert.match(source, /const nextTheme = input\.theme \?\? websiteProjectThemePayload\(current\.theme\)[\s\S]*theme = \$5::jsonb/);
  assert.match(source, /const nextNavigation = input\.navigation \?\? websiteProjectNavigationPayload\(current\.navigation\)[\s\S]*id = ANY\(\$3::uuid\[\]\)[\s\S]*navigation = \$6::jsonb/);
  assert.match(source, /WHERE id::text = \$1 AND company_id = \$2/);
  assert.match(source, /WHERE id::text = \$1 AND project_id::text = \$2 AND company_id = \$3/);
});
