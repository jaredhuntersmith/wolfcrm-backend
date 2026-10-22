import { createHash } from 'node:crypto';

export const ACCOUNT_MESSAGES = Object.freeze({
  account_locked: 'Your account is locked by your administrator.',
  account_disabled: 'Your account has been disabled.'
});
export const sessionDigest = token => createHash('sha256').update(token).digest('hex');
export function accountDenial(row) {
  const code = row?.deleted_at ? 'account_disabled' : row?.locked_at ? 'account_locked' : null;
  return code ? {error:code,message:ACCOUNT_MESSAGES[code]} : null;
}
export async function deniedSession(db, token) {
  const row=(await db.query('SELECT reason FROM revoked_account_sessions WHERE token_hash=$1 AND expires_at>now()',[sessionDigest(token)])).rows[0];
  return row ? {error:row.reason,message:ACCOUNT_MESSAGES[row.reason]} : null;
}
export async function revokeAccountSessions(db, userId, reason) {
  const sessions=(await db.query('DELETE FROM sessions WHERE user_id=$1 RETURNING token',[userId])).rows;
  for(const {token} of sessions) await db.query(`INSERT INTO revoked_account_sessions(token_hash,user_id,reason) VALUES($1,$2,$3)
    ON CONFLICT(token_hash) DO UPDATE SET reason=EXCLUDED.reason,expires_at=now()+interval '31 days'`,[sessionDigest(token),userId,reason]);
  // Tokens revoked for a prior lock should report a later disable consistently.
  if(reason==='account_disabled')await db.query('UPDATE revoked_account_sessions SET reason=$2 WHERE user_id=$1',[userId,reason]);
  for(const table of ['magic_tokens','password_reset_codes'])if((await db.query('SELECT to_regclass($1) AS name',[table])).rows[0].name)
    await db.query(`DELETE FROM ${table} WHERE email IN (SELECT email FROM users WHERE id=$1)`,[userId]);
  if((await db.query("SELECT to_regclass('mcp_tokens') AS name")).rows[0].name)
    await db.query('DELETE FROM mcp_tokens WHERE connection_id IN (SELECT id FROM mcp_connections WHERE user_id=$1)',[userId]);
  if((await db.query("SELECT to_regclass('comms_presence') AS name")).rows[0].name)
    await db.query('DELETE FROM comms_presence WHERE user_id=$1',[userId]);
  if((await db.query("SELECT to_regclass('wolf_assistant_runs') AS name")).rows[0].name)
    await db.query("UPDATE wolf_assistant_runs SET cancel_requested=true WHERE user_id=$1 AND status IN ('queued','running','waiting_approval','waiting_client')",[userId]);
  if((await db.query("SELECT to_regclass('focus_jobs') AS name")).rows[0].name)
    await db.query("UPDATE focus_jobs SET state='cancelled',lease_token=NULL,lease_expires_at=NULL WHERE user_id=$1 AND state IN ('queued','leased')",[userId]);
  if((await db.query("SELECT to_regclass('device_tokens') AS name")).rows[0].name)
    await db.query('DELETE FROM device_tokens WHERE user_id=$1',[userId]);
}
