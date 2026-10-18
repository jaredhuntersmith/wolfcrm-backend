// Only MCP-owned transient authentication/proposal data is expired here. Business
// records and minimized audit entries are preserved. Tokens remain long enough to
// detect refresh replay throughout their connection's absolute lifetime.
export async function cleanupMCP(pool){
 await pool.query('DELETE FROM mcp_browser_requests WHERE expires_at<now()');
 await pool.query("DELETE FROM mcp_codes WHERE expires_at<now()-interval '1 day'");
 await pool.query("INSERT INTO mcp_audit(connection_id,company_id,user_id,operation,outcome) SELECT p.connection_id,g.company_id,g.user_id,p.operation,'approval_expired' FROM mcp_approvals p JOIN mcp_connections g ON g.id=p.connection_id WHERE p.state='pending' AND p.expires_at<now()");
 await pool.query("UPDATE mcp_approvals SET payload=NULL,state='rejected' WHERE state='pending' AND expires_at<now()");
 await pool.query("DELETE FROM mcp_tokens t USING mcp_connections c WHERE c.id=t.connection_id AND c.expires_at<now()-interval '1 day'");
 await pool.query("DELETE FROM mcp_clients c WHERE c.created_at<now()-interval '1 day' AND NOT EXISTS(SELECT 1 FROM mcp_connections g WHERE g.client_id=c.id) AND NOT EXISTS(SELECT 1 FROM mcp_browser_requests r WHERE r.params->>'client_id'=c.id)");
 await pool.query("DELETE FROM mcp_rate_limits WHERE window_start<now()-interval '1 day'");
}
