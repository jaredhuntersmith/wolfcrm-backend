function list(value) {
  return Array.isArray(value) ? value.filter(Boolean).map(String) : [];
}

function humanizeSegment(segment) {
  return segment
    .replace(/_/g, " ")
    .replace(/\b\w/g, char => char.toUpperCase());
}

const friendlyRequirementNames = new Map([
  ["business_profile.url", "Business website"],
  ["business_profile.mcc", "Business category"],
  ["business_profile.product_description", "Business product or service description"],
  ["company.address.city", "Company city"],
  ["company.address.line1", "Company street address"],
  ["company.address.postal_code", "Company postal code"],
  ["company.address.state", "Company state"],
  ["company.name", "Company legal name"],
  ["company.phone", "Company phone number"],
  ["external_account", "Bank account for payouts"],
  ["individual.address.city", "Owner city"],
  ["individual.address.line1", "Owner street address"],
  ["individual.address.postal_code", "Owner postal code"],
  ["individual.address.state", "Owner state"],
  ["individual.dob.day", "Owner date of birth"],
  ["individual.dob.month", "Owner date of birth"],
  ["individual.dob.year", "Owner date of birth"],
  ["individual.email", "Owner email"],
  ["individual.first_name", "Owner first name"],
  ["individual.id_number", "Owner SSN or tax ID"],
  ["individual.last_name", "Owner last name"],
  ["individual.phone", "Owner phone number"],
  ["individual.ssn_last_4", "Owner SSN last 4"],
  ["individual.verification.document", "Identity verification document"],
  ["individual.verification.additional_document", "Additional identity verification document"],
  ["representative.first_name", "Representative first name"],
  ["representative.last_name", "Representative last name"],
  ["representative.verification.document", "Representative identity verification document"],
  ["tos_acceptance.date", "Stripe terms of service acceptance"],
  ["tos_acceptance.ip", "Stripe terms of service acceptance"]
]);

export function friendlyStripeRequirement(key) {
  const raw = String(key || "").trim();
  if (!raw) return "Additional information";
  if (friendlyRequirementNames.has(raw)) return friendlyRequirementNames.get(raw);
  const parts = raw.split(".").filter(Boolean);
  if (!parts.length) return "Additional information";
  const last = parts[parts.length - 1];
  if (parts.includes("verification") && parts.includes("document")) {
    return parts.includes("company") ? "Company verification document" : "Identity verification document";
  }
  if (parts.includes("dob")) return "Date of birth";
  if (last === "id_number") return "Tax ID or identity number";
  if (last === "ssn_last_4") return "SSN last 4";
  if (last === "line1") return `${humanizeSegment(parts[0])} street address`;
  if (last === "postal_code") return `${humanizeSegment(parts[0])} postal code`;
  return humanizeSegment(parts.slice(-2).join(" "));
}

function normalizeErrors(errors) {
  return (Array.isArray(errors) ? errors : []).filter(Boolean).map(error => {
    const requirement = error.requirement || error.requirement_code || error.code || null;
    return {
      requirement,
      code: error.code || null,
      reason: error.reason || null,
      message: error.message || error.reason || (requirement ? friendlyStripeRequirement(requirement) : "Stripe needs more information")
    };
  });
}

export function calculateStripeConnectReadiness(account) {
  if (!account) {
    return {
      stripe_connect_status: "not_connected",
      stripe_charges_enabled: false,
      stripe_payouts_enabled: false,
      stripe_details_submitted: false,
      stripe_default_currency: null,
      stripe_requirements: {
        currently_due: [],
        eventually_due: [],
        past_due: [],
        pending_verification: [],
        disabled_reason: null,
        errors: [],
        friendly_currently_due: [],
        friendly_past_due: [],
        friendly_pending_verification: []
      },
      stripe_capabilities: {}
    };
  }

  const requirements = account.requirements || {};
  const currentlyDue = list(requirements.currently_due);
  const eventuallyDue = list(requirements.eventually_due);
  const pastDue = list(requirements.past_due);
  const pendingVerification = list(requirements.pending_verification);
  const errors = normalizeErrors(requirements.errors);
  const disabledReason = requirements.disabled_reason || null;
  const actionableDisabledReason = disabledReason && ![
    "requirements.pending_verification",
    "under_review"
  ].includes(disabledReason);
  const actionable = currentlyDue.length > 0 || pastDue.length > 0 || errors.length > 0 || !!actionableDisabledReason;

  let status = "verification_pending";
  if (account.charges_enabled) status = "ready";
  else if (!account.details_submitted) status = "setup_incomplete";
  else if (actionable) status = "action_required";
  else if (pendingVerification.length > 0 || disabledReason === "requirements.pending_verification" || disabledReason === "under_review") status = "verification_pending";

  const capabilities = account.capabilities && typeof account.capabilities === "object" ? account.capabilities : {};
  return {
    stripe_connect_status: status,
    stripe_charges_enabled: !!account.charges_enabled,
    stripe_payouts_enabled: !!account.payouts_enabled,
    stripe_details_submitted: !!account.details_submitted,
    stripe_default_currency: account.default_currency || null,
    stripe_requirements: {
      currently_due: currentlyDue,
      eventually_due: eventuallyDue,
      past_due: pastDue,
      pending_verification: pendingVerification,
      disabled_reason: disabledReason,
      errors,
      friendly_currently_due: currentlyDue.map(friendlyStripeRequirement),
      friendly_past_due: pastDue.map(friendlyStripeRequirement),
      friendly_pending_verification: pendingVerification.map(friendlyStripeRequirement)
    },
    stripe_capabilities: {
      card_payments: capabilities.card_payments || null,
      transfers: capabilities.transfers || null
    }
  };
}
