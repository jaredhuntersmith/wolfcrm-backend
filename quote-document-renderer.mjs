// Canonical shared quote export layout. Sync to Web with scripts/sync-quote-renderer.mjs.
const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const RENDER_SCALE = 2;
// The long-form PNG stitches every rendered page into one browser canvas.
// Staying below common 32K canvas-height limits keeps both formats reliable.
const MAX_EXPORT_PAGES = 18;
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function optionalString(value) {
    return typeof value === "string" && value.trim() ? value.trim() : null;
}
function requiredNumber(value, name) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new Error(`WolfCRM returned invalid ${name} quote settings.`);
    }
    return Math.round(value);
}
export function parseQuoteExportSettings(value) {
    if (!isRecord(value) || typeof value.tax_enabled !== "boolean") {
        throw new Error("WolfCRM returned invalid Quote document settings.");
    }
    return {
        tagline: optionalString(value.tagline) ?? "Thank you for the opportunity to earn your business!",
        phone: optionalString(value.phone),
        email: optionalString(value.email),
        website: optionalString(value.website),
        notes: optionalString(value.notes),
        tax_enabled: value.tax_enabled,
        tax_rate_basis_points: Math.max(0, requiredNumber(value.tax_rate_basis_points, "tax")),
        valid_for_days: Math.max(1, requiredNumber(value.valid_for_days, "valid-for")),
        company_name: optionalString(value.company_name),
        company_logo_data_url: optionalString(value.company_logo_data_url),
        company_phone: optionalString(value.company_phone),
        company_email: optionalString(value.company_email),
        company_website: optionalString(value.company_website),
        company_address: optionalString(value.company_address),
    };
}
export function quoteDocumentTotals(quote, settings, pricing) {
    if (pricing)
        return { subtotal: pricing.subtotal_cents - pricing.discount_cents, tax: pricing.tax_cents, total: pricing.total_cents };
    const subtotal = Math.max(0, Math.round(quote.total_cents));
    const tax = settings.tax_enabled
        ? Math.round((subtotal * Math.max(0, settings.tax_rate_basis_points)) / 10_000)
        : 0;
    return { subtotal, tax, total: subtotal + tax };
}
export function quoteExportFilename(contactName, extension) {
    const cleaned = contactName
        .replace(/[\\/?%*|"<>:\u0000-\u001f]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 100);
    return `${cleaned || "Quote"}${cleaned ? " - Quote" : ""}.${extension}`;
}
function wrapPlainText(value, limit) {
    if (!value.trim())
        return [];
    const result = [];
    for (const paragraph of value.replace(/\r\n?/g, "\n").split("\n")) {
        const words = paragraph.trim().split(/\s+/).filter(Boolean);
        if (!words.length) {
            result.push("");
            continue;
        }
        let line = "";
        for (const word of words) {
            if (word.length > limit) {
                if (line)
                    result.push(line);
                for (let index = 0; index < word.length; index += limit)
                    result.push(word.slice(index, index + limit));
                line = "";
            }
            else if (!line) {
                line = word;
            }
            else if (`${line} ${word}`.length <= limit) {
                line = `${line} ${word}`;
            }
            else {
                result.push(line);
                line = word;
            }
        }
        if (line)
            result.push(line);
    }
    return result;
}
function itemHeight(item) {
    const nameHeight = (item.name_lines?.length ?? wrapPlainText(item.name.trim() || "Service", 28).length) * 15;
    const descriptionHeight = item.description_lines?.length ? 6 + item.description_lines.length * 13 : 0;
    return Math.max(22, nameHeight + descriptionHeight) + 9;
}
export function buildQuoteExportPages(quote, settings, pricing) {
    const pricedByID = new Map(pricing?.line_items.filter(item => item.id).map(item => [item.id, item]));
    const items = quote.line_items.length ? quote.line_items.map((item, index) => {
        const legacyRow = pricing?.line_items[index];
        const priced = item.id ? pricedByID.get(item.id) ?? (!legacyRow?.id ? legacyRow : undefined) : legacyRow;
        if (pricing && (!priced || !Number.isSafeInteger(priced.line_total_cents)))
            throw new Error("Quote pricing changed. Refresh this quote before exporting.");
        return { ...item, line_total_cents: priced?.line_total_cents };
    }) : [{ name: "Service", qty: 1, price_cents: 0 }];
    const pages = [];
    const freshPage = () => { const page = { items: [], first: pages.length === 0, showTotals: false, noteLines: [] }; pages.push(page); return page; };
    let page = freshPage();
    for (const item of items) {
        const description = wrapPlainText(item.description ?? "", 58);
        let continuation = false;
        do {
            const nameLines = wrapPlainText(`${item.name.trim() || "Service"}${continuation ? " (continued)" : ""}`, 28);
            let available = (page.first ? 310 : 551) - page.items.reduce((height, row) => height + itemHeight(row), 0);
            const minimum = Math.max(22, nameLines.length * 15 + (description.length ? 19 : 0)) + 9;
            if (page.items.length && available < minimum) {
                page = freshPage();
                available = 551;
            }
            const count = Math.max(0, Math.floor((available - nameLines.length * 15 - 15) / 13));
            const fragment = { ...item, name_lines: nameLines, description_lines: description.splice(0, count), continuation };
            page.items.push(fragment);
            if (description.length) {
                page = freshPage();
                continuation = true;
            }
        } while (description.length);
    }
    const publicContent = [settings.notes, quote.quote_options?.public_notes, quote.quote_options?.scope_exclusions ? `Not included / Scope exclusions\n${quote.quote_options.scope_exclusions}` : null].filter(Boolean).join("\n\n");
    const notes = wrapPlainText(publicContent, 58);
    const last = pages[pages.length - 1];
    const tableBottom = (last.first ? 388 : 147) + last.items.reduce((total, item) => total + itemHeight(item), 0);
    const totalsHeight = 140 + ((pricing?.discount_cents || 0) > 0 ? 26 : 0);
    const inlineNoteCapacity = Math.max(0, Math.floor((700 - Math.max(tableBottom + 22, last.first ? 500 : 150) - totalsHeight - 65) / 15));
    if (Math.max(tableBottom + 22, last.first ? 500 : 150) + totalsHeight <= 715 && inlineNoteCapacity >= notes.length) {
        last.showTotals = true;
        last.noteLines = notes;
    }
    else {
        const firstNotes = notes.splice(0, 20);
        pages.push({ items: [], first: false, showTotals: true, noteLines: firstNotes });
        while (notes.length)
            pages.push({ items: [], first: false, showTotals: false, noteLines: notes.splice(0, 34) });
    }
    if (pages.length > MAX_EXPORT_PAGES) {
        throw new Error("This Quote is too long to export safely. Shorten its service list or document notes and try again.");
    }
    return pages;
}
const money = (cents) => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
function quoteDate(value) {
    if (!value)
        return new Intl.DateTimeFormat("en-US", { dateStyle: "long" }).format(new Date());
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("en-US", { dateStyle: "long" }).format(date);
}
function quantity(value) {
    return new Intl.NumberFormat("en-US", { maximumFractionDigits: 3 }).format(value);
}
function lineAmount(item) {
    return Math.max(0, Math.round(item.qty * item.price_cents));
}
function setFont(context, size, weight = 400) {
    context.font = `${weight} ${size}px Arial, sans-serif`;
}
function drawText(context, value, x, y, options = {}) {
    context.fillStyle = options.color ?? "#263229";
    context.textAlign = options.align ?? "left";
    context.textBaseline = "top";
    setFont(context, options.size ?? 11, options.weight ?? 400);
    context.fillText(value, x, y);
}
function wrappedLines(context, value, width) {
    const lines = [];
    for (const paragraph of value.replace(/\r\n?/g, "\n").split("\n")) {
        const words = paragraph.trim().split(/\s+/).filter(Boolean);
        if (!words.length) {
            lines.push("");
            continue;
        }
        let line = "";
        for (const word of words) {
            const candidate = line ? `${line} ${word}` : word;
            if (context.measureText(candidate).width <= width || !line)
                line = candidate;
            else {
                lines.push(line);
                line = word;
            }
        }
        if (line)
            lines.push(line);
    }
    return lines;
}
function drawWrappedText(context, value, x, y, width, options = {}) {
    setFont(context, options.size ?? 11, options.weight ?? 400);
    const lines = wrappedLines(context, value, width);
    const lineHeight = options.lineHeight ?? 16;
    lines.forEach((line, index) => drawText(context, line, x, y + index * lineHeight, options));
    return Math.max(lineHeight, lines.length * lineHeight);
}
function drawRule(context, x, y, width, color = "#b7beb8") {
    context.strokeStyle = color;
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(x, y + 0.5);
    context.lineTo(x + width, y + 0.5);
    context.stroke();
}
function businessLines(settings) {
    return [
        settings.phone ?? settings.company_phone,
        settings.email ?? settings.company_email,
        settings.website ?? settings.company_website,
    ].filter((value) => Boolean(value));
}
function customerLines(contact) {
    return [contact.address, contact.phone, contact.email].filter((value) => Boolean(value?.trim()));
}
function drawFirstPageHeader(context, document, logo) {
    const { contact, quote, settings } = document;
    if (logo)
        context.drawImage(logo, 40, 42, 54, 54);
    drawText(context, settings.company_name ?? "Company", 40, 118, { size: 21, weight: 700 });
    drawWrappedText(context, settings.tagline, 40, 151, 250, { size: 11, lineHeight: 16 });
    context.strokeStyle = "#aeb7b0";
    context.strokeRect(336.5, 47.5, 235, 122);
    drawText(context, "QUOTE", 350, 62, { size: 20, weight: 700 });
    drawRule(context, 336, 94, 235);
    drawText(context, "DATE", 350, 108, { color: "#758078", size: 9 });
    drawText(context, quoteDate(quote.created_at), 558, 106, { size: 10, align: "right" });
    drawRule(context, 336, 132, 235);
    drawText(context, "VALID FOR", 350, 145, { color: "#758078", size: 9 });
    drawText(context, `${settings.valid_for_days} Days`, 558, 143, { size: 10, align: "right" });
    drawText(context, "QUOTE PREPARED FOR", 40, 218, { color: "#7d867f", size: 10 });
    drawRule(context, 40, 237, 232);
    drawText(context, contact.name || "Customer", 40, 251, { size: 11, weight: 700 });
    customerLines(contact).slice(0, 4).forEach((line, index) => drawText(context, line, 40, 272 + index * 16, { size: 10 }));
    drawText(context, "CONTACT US", 336, 218, { color: "#7d867f", size: 10 });
    drawRule(context, 336, 237, 235);
    if (settings.company_address)
        drawWrappedText(context, settings.company_address, 336, 251, 235, { size: 10, lineHeight: 15 });
    businessLines(settings).slice(0, 3).forEach((line, index) => drawText(context, line, 336, 283 + index * 16, { size: 10 }));
}
function drawTable(context, items, startY) {
    if (!items.length)
        return startY;
    context.fillStyle = "#718078";
    context.fillRect(40, startY, 532, 29);
    drawText(context, "Services", 49, startY + 8, { color: "#ffffff", size: 10, weight: 700 });
    drawText(context, "qty", 396, startY + 8, { color: "#ffffff", size: 10, align: "right" });
    drawText(context, "unit price", 491, startY + 8, { color: "#ffffff", size: 10, align: "right" });
    drawText(context, "amount", 563, startY + 8, { color: "#ffffff", size: 10, align: "right" });
    let y = startY + 42;
    items.forEach((item) => {
        const names = item.name_lines ?? wrapPlainText(item.name.trim() || "Service", 28);
        names.forEach((line, index) => drawText(context, line, 49, y + index * 15, { size: 10 }));
        if (!item.continuation) {
            drawText(context, quantity(item.qty), 396, y, { color: "#6f7972", size: 10, align: "right" });
            drawText(context, money(item.price_cents), 491, y, { color: "#6f7972", size: 10, align: "right" });
            drawText(context, money(item.line_total_cents ?? lineAmount(item)), 563, y, { size: 10, align: "right" });
        }
        item.description_lines?.forEach((line, index) => drawText(context, line, 49, y + names.length * 15 + 6 + index * 13, { size: 9, color: "#4f5c53" }));
        y += itemHeight(item);
    });
    drawRule(context, 40, y, 532);
    return y;
}
function drawTotals(context, document, startY) {
    const totals = quoteDocumentTotals(document.quote, document.settings, document.pricing);
    let y = startY;
    drawText(context, "Subtotal", 350, y, { size: 11 });
    drawText(context, money(document.pricing?.subtotal_cents ?? totals.subtotal), 572, y, { size: 11, align: "right" });
    y += 26;
    if ((document.pricing?.discount_cents || 0) > 0) {
        drawText(context, "Discount", 350, y, { size: 11 });
        drawText(context, `−${money(document.pricing.discount_cents)}`, 572, y, { size: 11, align: "right" });
        y += 26;
    }
    const taxRate = document.pricing?.tax_rate_basis_points ?? document.settings.tax_rate_basis_points;
    if (document.pricing ? taxRate > 0 : document.settings.tax_enabled) {
        drawText(context, `${document.pricing?.tax_inclusive ? "Included tax" : "Tax"} (${(taxRate / 100).toFixed(2)}%)`, 350, y, { size: 11 });
        drawText(context, money(totals.tax), 572, y, { size: 11, align: "right" });
        y += 26;
    }
    drawRule(context, 350, y - 5, 222);
    drawText(context, "Total", 350, y + 10, { size: 18, weight: 700 });
    drawText(context, money(totals.total), 572, y + 8, { size: 18, weight: 700, align: "right" });
    y += 48;
    if (document.pricing && document.pricing.deposit_cents > 0) {
        drawText(context, "Deposit after signing", 350, y, { size: 10 });
        drawText(context, money(document.pricing.deposit_cents), 572, y, { size: 10, align: "right" });
        y += 26;
    }
    return y;
}
function drawNotes(context, lines, startY) {
    if (!lines.length)
        return startY;
    drawText(context, "NOTES", 40, startY, { color: "#7d867f", size: 10 });
    drawRule(context, 40, startY + 19, 300);
    lines.forEach((line, index) => drawText(context, line, 40, startY + 32 + index * 15, { size: 10 }));
    return startY + 42 + lines.length * 15;
}
function drawFooter(context, document, pageIndex, pageCount) {
    drawRule(context, 40, 738, 532);
    drawText(context, document.settings.company_name ?? "Company", 40, 751, { color: "#7d867f", size: 8 });
    drawText(context, document.settings.website ?? document.settings.company_website ?? "", 306, 751, { color: "#7d867f", size: 8, align: "center" });
    if (pageCount > 1)
        drawText(context, `Page ${pageIndex + 1} of ${pageCount}`, 572, 751, { color: "#7d867f", size: 8, align: "right" });
}
export function drawPage(context, document, page, pageIndex, pageCount, logo) {
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, PAGE_WIDTH, PAGE_HEIGHT);
    if (page.first)
        drawFirstPageHeader(context, document, logo);
    else {
        drawText(context, "QUOTE", 40, 56, { size: 19, weight: 700 });
        drawText(context, document.contact.name || "Customer", 572, 60, { color: "#6f7972", size: 10, align: "right" });
    }
    const tableBottom = drawTable(context, page.items, page.first ? 346 : 105);
    let contentBottom = tableBottom;
    if (page.showTotals)
        contentBottom = drawTotals(context, document, Math.max(tableBottom + 22, page.first ? 500 : 150));
    if (page.noteLines.length)
        contentBottom = drawNotes(context, page.noteLines, Math.max(contentBottom + 20, page.showTotals ? 285 : 120));
    void contentBottom;
    drawFooter(context, document, pageIndex, pageCount);
}
