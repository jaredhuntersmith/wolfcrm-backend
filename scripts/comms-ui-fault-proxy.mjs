// Disposable loopback-only fault injection for native Retry/error acceptance.
import http from 'node:http';
import {readFileSync,writeFileSync,unlinkSync} from 'node:fs';
const fixture=JSON.parse(readFileSync('/tmp/wolf-comms-ui-session.json'));
const upstream=new URL(fixture.origin);
if(upstream.protocol!=='http:'||upstream.hostname!=='127.0.0.1'||!upstream.port)throw Error('Local fixture required');
const control='/tmp/wolf-comms-ui-fault-mode',state='/tmp/wolf-comms-ui-proxy.json';
writeFileSync(control,'html',{mode:0o600});
const server=http.createServer((req,res)=>{
 const path=new URL(req.url,'http://127.0.0.1').pathname;
 const mode=readFileSync(control,'utf8').trim();
 if(mode==='html'&&['/api/comms/bootstrap','/api/comms/notifications'].includes(path)){
  res.writeHead(404,{'Content-Type':'text/html','X-Request-ID':'local-legacy-fixture'});res.end('<!DOCTYPE html><html><pre>Cannot GET '+path+'</pre></html>');return;
 }
 const relay=http.request({hostname:'127.0.0.1',port:upstream.port,path:req.url,method:req.method,headers:{...req.headers,host:upstream.host}},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
 relay.on('error',()=>{res.writeHead(503,{'Content-Type':'application/json'});res.end('{"error":"local_fixture_unavailable"}');});req.pipe(relay);
});
server.listen(0,'127.0.0.1',()=>{writeFileSync(state,JSON.stringify({origin:'http://127.0.0.1:'+server.address().port,pid:process.pid}),{mode:0o600});console.log('Local error/retry proxy ready.');});
process.on('SIGTERM',()=>{server.closeAllConnections();server.close(()=>{for(const p of [state,control])try{unlinkSync(p);}catch{}process.exit(0);});});
