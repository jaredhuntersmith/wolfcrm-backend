import { QuoteContractError, quoteText, quoteInteger, normalizeQuoteTemplateDefaults } from "./quote-contract-domain.js";
const problem = (code, message, status = 400) => { throw new QuoteContractError(code, message, status); };
const uuid = value => {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) problem("agreement_id_invalid", "A valid record ID is required.");
  return value.toLowerCase();
};

export function normalizeAgreementContent(raw = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) problem("agreement_content_invalid", "Agreement content must be an object.");
  if (["deposit", "deposit_type", "deposit_required", "deposit_value", "quote_options"].some((key) => key in raw)) problem("template_defaults_invalid", "Place quote workflow settings in quote_defaults.");
  const roles = raw.required_signers ?? ["customer"];
  if (!Array.isArray(roles) || !roles.includes("customer") || roles.length > 3 || new Set(roles).size !== roles.length || roles.some((role) => !["customer", "customer_2", "business"].includes(role))) problem("agreement_signers_invalid", "Select the required customer and optional additional signer roles.");
  const documents = raw.documents ?? [];
  if (!Array.isArray(documents) || documents.length > 10) problem("agreement_documents_invalid", "Attach up to ten contract PDFs.");
  const boolean = (key) => { if (raw[key] != null && typeof raw[key] !== "boolean") problem("agreement_content_invalid", `${key} must be true or false.`); return raw[key] ?? false; };
  const position = raw.quote_position ?? "first";
  if (!["first", "last", "excluded"].includes(position)) problem("agreement_quote_position_invalid", "Place quote pages first, last, or preserve them as a separate referenced scope attachment.");
  const preference=key=>{if(raw[key]!=null&&typeof raw[key]!=="boolean")problem("agreement_content_invalid",`${key} must inherit or be true or false.`);return raw[key]??null;};
  const branding=raw.branding??{};
  if(!branding||typeof branding!=="object"||Array.isArray(branding))problem("agreement_branding_invalid","Choose valid business branding.");
  const color=branding.accent_color??null;
  if(color!==null&&(typeof color!=="string"||!/^#[0-9a-f]{6}$/i.test(color)))problem("agreement_branding_invalid","Choose a six-digit hex accent color.");
  if(branding.show_logo!=null&&typeof branding.show_logo!=="boolean")problem("agreement_branding_invalid","Logo visibility must be true or false.");
  const label=raw.estimate_label??"Quote";
  if(!["Estimate","Quote"].includes(label))problem("agreement_label_invalid","Choose Estimate or Quote.");
  return {
    agreement_text: quoteText(raw.agreement_text, "Agreement text", 100000),
    terms_text: quoteText(raw.terms_text, "Terms & Conditions", 100000),
    terms_asset_id: raw.terms_asset_id ? uuid(raw.terms_asset_id) : null,
    consent_text: quoteText(raw.consent_text, "Electronic signing consent", 10000),
    confirmation_text:quoteText(raw.confirmation_text,"Confirmation message",5000),estimate_label:"Quote",
    show_agreement: raw.show_agreement == null ? true : boolean("show_agreement"),
    show_terms: raw.show_terms == null ? true : boolean("show_terms"),
    quote_defaults: raw.quote_defaults == null ? null : normalizeQuoteTemplateDefaults(raw.quote_defaults),
    scope_exclusions:"",
    validity_days:raw.validity_days==null?null:quoteInteger(raw.validity_days,"Template validity",365,1),
    booking_preference:preference("booking_preference"),plan_offer_preference:preference("plan_offer_preference"),
    branding:{display_name:quoteText(branding.display_name,"Business display name",120).trim(),accent_color:color?.toUpperCase()??null,show_logo:branding.show_logo??true},
    show_customer_phone: boolean("show_customer_phone"), show_customer_email: boolean("show_customer_email"),
    required_signers: roles, quote_position: position,
    documents: documents.map((doc) => ({ asset_id: uuid(doc.asset_id), fields: doc.fields ?? [] })),
  };
}

