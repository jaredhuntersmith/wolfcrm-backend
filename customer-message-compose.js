export const CUSTOMER_MESSAGE_MAX_LENGTH = 1600;

export class CustomerMessageComposeError extends Error {
  constructor(code, message, { statusCode = 400, details = null } = {}) {
    super(message);
    this.name = "CustomerMessageComposeError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function validateCustomerMessageCompose(value) {
  const contactId = typeof value?.contact_id === "string" ? value.contact_id.trim() : "";
  if (!contactId) {
    throw new CustomerMessageComposeError(
      "contact_required",
      "Choose a customer before sending this message.",
      { statusCode: 422 },
    );
  }

  if (typeof value?.body !== "string") {
    throw new CustomerMessageComposeError(
      "message_body_required",
      "Enter a message before sending.",
      { statusCode: 422 },
    );
  }
  const body = value.body.trim();
  if (!body) {
    throw new CustomerMessageComposeError(
      "message_body_required",
      "Enter a message before sending.",
      { statusCode: 422 },
    );
  }
  if (body.length > CUSTOMER_MESSAGE_MAX_LENGTH) {
    throw new CustomerMessageComposeError(
      "message_too_long",
      `Customer SMS messages cannot exceed ${CUSTOMER_MESSAGE_MAX_LENGTH.toLocaleString()} characters.`,
      {
        statusCode: 422,
        details: { max_length: CUSTOMER_MESSAGE_MAX_LENGTH },
      },
    );
  }

  return { contactId, body };
}
