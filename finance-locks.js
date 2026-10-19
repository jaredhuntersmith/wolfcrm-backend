// Shared accounting serialization, including the existing statement-close lock.
// Call inside the same transaction before reading/mutating finance rows. The
// request role can read companies but must never gain UPDATE just to take a lock.
// Finance row locks, source versions, space RLS and permissions remain separate.
export async function lockFinanceCompany(client, companyId) {
  await client.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [`${companyId}|accounting`]);
}
