import assert from "node:assert/strict";
import test from "node:test";
import {
  CUSTOMER_MESSAGE_MAX_LENGTH,
  CustomerMessageComposeError,
  validateCustomerMessageCompose,
} from "../customer-message-compose.js";

test("new customer messages require a contact and non-empty body", () => {
  assert.throws(
    () => validateCustomerMessageCompose({ body: "Hello" }),
    (error) => error instanceof CustomerMessageComposeError
      && error.code === "contact_required"
      && error.statusCode === 422,
  );
  assert.throws(
    () => validateCustomerMessageCompose({ contact_id: "contact-1", body: "   " }),
    (error) => error instanceof CustomerMessageComposeError
      && error.code === "message_body_required",
  );
});

test("new customer message payloads are trimmed and bounded", () => {
  assert.deepEqual(
    validateCustomerMessageCompose({ contact_id: " contact-1 ", body: " Hello there " }),
    { contactId: "contact-1", body: "Hello there" },
  );
  assert.throws(
    () => validateCustomerMessageCompose({
      contact_id: "contact-1",
      body: "x".repeat(CUSTOMER_MESSAGE_MAX_LENGTH + 1),
    }),
    (error) => error instanceof CustomerMessageComposeError
      && error.code === "message_too_long"
      && error.details?.max_length === CUSTOMER_MESSAGE_MAX_LENGTH,
  );
});
