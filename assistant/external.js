import {executeRoute} from './routes.js';
import {dispatch,fault} from '../mcp/context.js';
import {getRecord} from '../mcp/registry.js';

// Only fixed, reviewed workflows. The model never supplies an endpoint or method.
export async function executeExternal({app,pool,actor,tool,input,revalidate}){
 if(['assistant_route_build','assistant_route_recalculate'].includes(tool))return executeRoute({app,pool,actor,tool,input,revalidate});
 if(tool!=='assistant_customer_message')throw fault(400,'external_operation_unavailable');
 await getRecord(pool,actor,'customer_conversations',input.conversation_id);
 const message=await dispatch(app,actor,'POST',`/api/phone/conversations/${input.conversation_id}/messages`,{body:input.body});
 const result=message?.message||message;
 return {entity:'customer_messages',id:String(result.id),conversation_id:input.conversation_id,status:result.message_status||'submitted',message:'Submitted through the canonical messaging service. Delivery is confirmed separately by provider status callbacks.'};
}
