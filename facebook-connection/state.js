// Propagation is conditional on the credential that produced the response. A slow
// response from an older authorization must never poison a successful reconnect.
const tables = {
  facebook: "facebook_connections",
  leads: "facebook_lead_connections",
  ads: "facebook_ads_connections",
};
function guard(origin, token) {
  if (!tables[origin] || !token)
    throw new Error("Credential snapshot required for shared Facebook state");
  return `EXISTS(SELECT 1 FROM ${tables[origin]} origin WHERE origin.company_id=$1 AND origin.token=$3)`;
}
export async function invalidateSharedAuthorization(
  db,
  company,
  error,
  origin,
  token,
) {
  const current = guard(origin, token),
    values = [company, error, token];
  await db.query(
    `UPDATE facebook_connections SET status='attention',error_code=$2,checked_at=now(),updated_at=now() WHERE company_id=$1 AND ${current}`,
    values,
  );
  await db.query(
    `UPDATE facebook_lead_connections SET status='attention',error_code=$2,updated_at=now() WHERE company_id=$1 AND unified AND ${current}`,
    values,
  );
  await db.query(
    `UPDATE facebook_ads_connections SET status='attention',error_code=$2,revision=revision+1,updated_at=now() WHERE company_id=$1 AND unified AND ${current}`,
    values,
  );
}
export const expiredAuthorization = (code) =>
  [
    "facebook_token_expired_reconnect",
    "facebook_reauthorize_required",
  ].includes(code);
export async function syncSharedPermissions(
  db,
  company,
  permissions,
  origin,
  token,
) {
  const current = guard(origin, token),
    values = [company, JSON.stringify(permissions), token];
  await db.query(
    `UPDATE facebook_connections SET permissions=$2,checked_at=now() WHERE company_id=$1 AND ${current}`,
    values,
  );
  if (origin !== "leads")
    await db.query(
      `UPDATE facebook_lead_connections SET permissions=$2,checked_at=now() WHERE company_id=$1 AND unified AND ${current}`,
      values,
    );
  if (origin !== "ads")
    await db.query(
      `UPDATE facebook_ads_connections SET revision=revision+CASE WHEN permissions<>$2::jsonb THEN 1 ELSE 0 END,permissions=$2,checked_at=now() WHERE company_id=$1 AND unified AND ${current}`,
      values,
    );
}
