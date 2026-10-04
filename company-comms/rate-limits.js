import {createHash} from 'node:crypto';
import {fail} from './access.js';
export async function installRateLimits(db){await db.query(`CREATE TABLE IF NOT EXISTS comms_rate_limits(subject text NOT NULL,bucket text NOT NULL,window_at timestamptz NOT NULL,count integer NOT NULL,PRIMARY KEY(subject,bucket,window_at));CREATE INDEX IF NOT EXISTS comms_rate_expiry ON comms_rate_limits(window_at);`);}
export function ratePolicy(method,path){
 if(/\/events$|\/presence$|\/processing$/.test(path)&&method==='GET')return {bucket:'catchup',limit:180};
 if(/\/search|\/sources\//.test(path))return {bucket:'search',limit:120};
 if(/\/exports$|\/export-context$/.test(path))return {bucket:'exports',limit:12};
 if(/\/calls\/[^/]+\/(join|accept)$|\/guest.*token/.test(path))return {bucket:'call_tokens',limit:60};
 if(/\/calls$|\/meetings$/.test(path)&&method==='POST')return {bucket:'call_create',limit:12};
 if(/\/messages$/.test(path)&&method==='POST')return {bucket:'message_send',limit:60};
 if(/\/membership|\/groups$/.test(path)&&method==='POST')return {bucket:'membership',limit:30};
 if(/\/uploads$|\/exports$|\/parts$|\/thumbnail$/.test(path)&&method==='POST')return {bucket:'uploads',limit:120};
 return {bucket:method==='GET'?'read':'mutation',limit:method==='GET'?240:120};
}
export async function takeRateLimit(db,req,{bucket,limit}=ratePolicy(req.method,req.originalUrl?.split('?')[0]||req.path||'')){
 const subject=req.userId?req.companyId+':'+req.userId:createHash('sha256').update('guest:'+String(req.ip||req.socket?.remoteAddress||'unknown')).digest('hex');
 const row=(await db.query(`INSERT INTO comms_rate_limits(subject,bucket,window_at,count) VALUES($1,$2,date_trunc('minute',now()),1) ON CONFLICT(subject,bucket,window_at) DO UPDATE SET count=LEAST(comms_rate_limits.count+1,1000000) RETURNING count`,[subject,bucket])).rows[0];
 if(row.count>limit)fail(429,'rate_limited','Too many requests. Wait a minute and retry.');
}
