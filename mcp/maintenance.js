// Only MCP-owned transient authentication/proposal data is expired here. Business
// records and minimized audit entries are preserved. Tokens remain long enough to
// detect refresh replay throughout their connection's absolute lifetime.
export async function cleanupMCP(pool){
 await pool.query('DELETE FROM mcp_browser_requests WHERE expires_at<now()');
 await pool.query("DELETE FROM mcp_codes WHERE expires_at<now()-interval '1 day'");
 await pool.query("UPDATE mcp_approvals SET payload=NULL,state='rejected' WHERE state='pending' AND expires_at<now()");
 await pool.query("DELETE FROM mcp_tokens t USING mcp_connections c WHERE c.id=t.connection_id AND c.expires_at<now()-interval '1 day'");
 await pool.query("DELETE FROM mcp_clients c WHERE c.created_at<now()-interval '1 day' AND NOT EXISTS(SELECT 1 FROM mcp_connections g WHERE g.client_id=c.id) AND NOT EXISTS(SELECT 1 FROM mcp_browser_requests r WHERE r.params->>'client_id'=c.id)");
 await pool.query("DELETE FROM mcp_rate_limits WHERE window_start<now()-interval '1 day'");
}
