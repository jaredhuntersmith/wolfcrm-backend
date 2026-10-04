import {conversationJoins,conversationAccessSQL} from '../access.js';

// Shared by search and the call directory before ordering/pagination. The
// caller also checks the target chat: source access never implies admission.
export function callReadSQL(actor,alias='cs') {
 return `(${alias}.company_id=$2 AND NOT EXISTS(SELECT 1 FROM comms_call_participants removed WHERE removed.call_id=${alias}.id AND removed.user_id=$1 AND removed.state='removed') AND (${alias}.meeting_id IS NULL OR EXISTS(
  SELECT 1 FROM comms_meetings source_meeting JOIN conversations c ON c.id=COALESCE(source_meeting.source_conversation_id,source_meeting.conversation_id) ${conversationJoins}
  WHERE source_meeting.id=${alias}.meeting_id AND source_meeting.company_id=$2 AND source_meeting.conversation_id=${alias}.conversation_id
   AND (source_meeting.host_user_id=$1 OR EXISTS(SELECT 1 FROM comms_meeting_attendees attendee WHERE attendee.meeting_id=source_meeting.id AND attendee.user_id=$1))
   AND (source_meeting.status<>'canceled' OR ${alias}.status IN('ended','canceled','declined','missed','failed')) AND ${conversationAccessSQL(actor)}
 )))`;
}
