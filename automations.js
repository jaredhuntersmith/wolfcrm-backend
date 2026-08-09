import { randomUUID } from "crypto";
import net from "net";

const AUTOMATION_LIMITS = {
  maxNodesPerRun: 5000,
  maxNodeAttempts: 8,
  maxChildDepth: 12,
  maxRuntimeHours: 24 * 30,
  eventBatchSize: 25,
  waitBatchSize: 25,
  foreachDefaultMaxItems: 100,
  foreachHardMaxItems: 500,
  foreachMaxParallelism: 10,
  maxScopeDepth: 8,
  maxCollectionOutputItems: 500,
  maxJsonBytes: 250000
};

const AUTOMATION_SAFETY_DEFAULTS = {
  maxActiveRunsPerAutomation: 25,
  maxActiveRunsPerSubject: 1,
  maxCompanyActiveRuns: 100,
  runStartsPerMinute: 120,
  nodeExecutionsPerMinute: 2000,
  maxCustomerMessagesPerRun: 25,
  maxInternalMessagesPerRun: 100,
  maxWebhookActionsPerRun: 50,
  maxChildRunsPerRun: 50,
  maxTotalIterationsPerRun: 1000,
  maxRetryDelaySeconds: 86400,
  eventMaxAttempts: 5,
  processorLeaseSeconds: 120,
  nodeLeaseSeconds: 300
};

let ctx = null;

class AutomationError extends Error {
  constructor(code, message, options = {}) {
    super(message || code);
    this.code = code || "unknown_error";
    this.errorClass = options.errorClass || classifyErrorCode(this.code);
    this.retryable = options.retryable ?? isRetryableErrorCode(this.code);
    this.details = options.details || {};
  }
}

const SIDE_EFFECT_FREE_ACTIONS = new Set([
  "contacts.search", "jobs.search", "tasks.search", "map.search_pins", "route.get_stops", "quotes.search", "payments.search", "service_plans.search", "employees.search",
  "collection.filter", "collection.map", "collection.sort", "collection.limit", "collection.first", "collection.last", "collection.count", "collection.unique", "collection.concat", "collection.flatten", "collection.contains",
  "object.get", "object.build", "coalesce", "math", "text", "date"
]);

const CORE_TRIGGERS = new Set([
  "manual",
  "contact.created", "contact.updated", "contact.tag_added", "contact.tag_removed",
  "pipeline.stage_changed", "pipeline.won", "pipeline.lost",
  "job.created", "job.completed",
  "task.due",
  "sms.received", "sms.reply_received",
  "call.missed",
  "payment.succeeded", "payment.failed",
  "service_plan.service_due",
  "map.pin_status_changed",
  "time_clock.clocked_in", "time_clock.clocked_out"
]);

const HIDDEN_TRIGGERS = new Set([
  "contact.restored", "contact.assigned", "contact.reassigned", "contact.unassigned",
  "lead.assigned", "lead.reassigned",
  "pipeline.salesperson_assigned", "pipeline.salesperson_changed", "pipeline.salesperson_removed",
  "job.restored", "job.canceled", "job.started",
  "call.declined",
  "route.created", "route.updated", "route.deleted", "route.stop_added", "route.stop_removed", "route.reordered",
  "route.assigned", "route.started", "route.completed", "route.stop_completed", "route.stop_skipped", "route.all_stops_completed", "route.scheduled",
  "invoice.created", "invoice.issued", "invoice.updated", "invoice.due", "invoice.overdue", "invoice.paid", "invoice.voided", "invoice.deleted", "invoice.total_changed",
  "map.pin_list_changed", "map.pin_added_to_list", "map.pin_removed_from_list", "map.pin_note_added", "map.pin_visited", "map.pin_knocked",
  "canvass.knock_recorded", "canvass.outcome_recorded"
]);

const CORE_ACTIONS = new Set([
  "contact.create", "contact.add_tag", "contact.update_fields",
  "pipeline.create_opportunity", "pipeline.move_stage",
  "task.create", "task.complete",
  "job.create", "job.mark_completed",
  "sms.send",
  "notification.send_push",
  "payment.create_payment_link",
  "service_plan.create_service_task"
]);

const HIDDEN_ACTIONS = new Set([
  "contact.restore", "contact.assign_user", "contact.unassign_user",
  "pipeline.assign_salesperson", "pipeline.remove_salesperson",
  "invoice.generate_pdf",
  "measurement.link_pin",
  "job.cancel", "job.restore",
  "map.add_to_route",
  "route.create", "route.delete", "route.add_stop", "route.remove_stop", "route.add_contact", "route.add_pin", "route.add_job",
  "route.assign_user", "route.set_date", "route.optimize", "route.mark_started", "route.mark_completed", "route.complete_stop", "route.skip_stop",
  "route.get_stops",
  "quote.create_invoice",
  "invoice.create", "invoice.issue", "invoice.set_due_date", "invoice.void", "invoice.create_payment_request", "invoice.send_payment_link", "invoice.create_followup_task"
]);

const DEPRECATED_REPLACEMENTS = {
  "contact.name_changed": "contact.field_changed",
  "contact.phone_changed": "contact.field_changed",
  "contact.email_changed": "contact.field_changed",
  "contact.address_changed": "contact.field_changed",
  "contact.value_changed": "contact.field_changed",
  "contact.job_type_changed": "contact.field_changed",
  "contact.source_changed": "contact.field_changed",
  "contact.u1_changed": "contact.field_changed",
  "contact.u2_changed": "contact.field_changed",
  "contact.u3_changed": "contact.field_changed",
  "contact.u4_changed": "contact.field_changed",
  "contact.u5_changed": "contact.field_changed",
  "job.start_changed": "job.field_changed",
  "job.end_changed": "job.field_changed",
  "job.date_changed": "job.field_changed",
  "job.price_changed": "job.field_changed",
  "job.material_cost_changed": "job.field_changed",
  "job.color_changed": "job.field_changed",
  "job.contact_changed": "job.field_changed",
  "quote.mark_sent": "quote.set_status",
  "quote.mark_accepted": "quote.set_status",
  "quote.mark_declined": "quote.set_status",
  "contact.set_source": "contact.update_fields",
  "contact.set_value": "contact.update_fields",
  "contact.set_job_type": "contact.update_fields",
  "contact.set_custom_field": "contact.update_fields"
};

function triggerVisibility(key) {
  if (HIDDEN_TRIGGERS.has(key)) return "hidden";
  if (CORE_TRIGGERS.has(key)) return "core";
  return "advanced";
}

function actionVisibility(key) {
  if (HIDDEN_ACTIONS.has(key)) return "hidden";
  if (CORE_ACTIONS.has(key)) return "core";
  return "advanced";
}

function deprecationFor(key) {
  const replacement = DEPRECATED_REPLACEMENTS[key];
  if (!replacement) return {};
  return { deprecated: true, deprecated_reason: "Use the broader configurable node in new automations.", replacement_key: replacement };
}

const triggerCatalog = [
  ["manual", "Manual", "Manual", "Starts when an employer manually runs the automation.", ["generic"], ["manual"]],
  ["contact.created", "Contact Created", "Contacts", "A contact was created.", ["contact"], ["contact.created"]],
  ["contact.updated", "Contact Updated", "Contacts", "A contact was updated.", ["contact"], ["contact.updated"]],
  ["contact.deleted", "Contact Deleted", "Contacts", "A contact was deleted.", ["contact"], ["contact.deleted"]],
  ["contact.restored", "Contact Restored", "Contacts", "A deleted contact was restored.", ["contact"], ["contact.restored"]],
  ["contact.field_changed", "Contact Field Changed", "Contacts", "A selected contact field changed.", ["contact"], ["contact.field_changed"]],
  ["contact.name_changed", "Contact Name Changed", "Contacts", "The contact name changed.", ["contact"], ["contact.name_changed"]],
  ["contact.phone_changed", "Contact Phone Changed", "Contacts", "The contact phone changed.", ["contact"], ["contact.phone_changed"]],
  ["contact.email_changed", "Contact Email Changed", "Contacts", "The contact email changed.", ["contact"], ["contact.email_changed"]],
  ["contact.address_changed", "Contact Address Changed", "Contacts", "The contact address changed.", ["contact"], ["contact.address_changed"]],
  ["contact.value_changed", "Contact Value Changed", "Contacts", "The contact value changed.", ["contact"], ["contact.value_changed"]],
  ["contact.job_type_changed", "Contact Job Type Changed", "Contacts", "The contact job type changed.", ["contact"], ["contact.job_type_changed"]],
  ["contact.source_changed", "Contact Source Changed", "Contacts", "The contact source changed.", ["contact"], ["contact.source_changed"]],
  ["contact.assigned", "Contact Assigned", "Contacts", "A contact was assigned where supported.", ["contact"], ["contact.assigned"]],
  ["contact.reassigned", "Contact Reassigned", "Contacts", "A contact assignment changed where supported.", ["contact"], ["contact.reassigned"]],
  ["contact.unassigned", "Contact Unassigned", "Contacts", "A contact was unassigned where supported.", ["contact"], ["contact.unassigned"]],
  ["contact.tag_added", "Contact Tag Added", "Contacts", "One or more tags were added to a contact.", ["contact"], ["contact.tag_added"]],
  ["contact.tag_removed", "Contact Tag Removed", "Contacts", "One or more tags were removed from a contact.", ["contact"], ["contact.tag_removed"]],
  ["contact.tags_changed", "Contact Tags Changed", "Contacts", "The contact tag set changed.", ["contact"], ["contact.tags_changed"]],
  ["contact.custom_field_changed", "Contact Custom Field Changed", "Contacts", "One of the contact custom fields changed.", ["contact"], ["contact.custom_field_changed"]],
  ["contact.u1_changed", "Custom Field 1 Changed", "Contacts", "Contact custom field 1 changed.", ["contact"], ["contact.u1_changed"]],
  ["contact.u2_changed", "Custom Field 2 Changed", "Contacts", "Contact custom field 2 changed.", ["contact"], ["contact.u2_changed"]],
  ["contact.u3_changed", "Custom Field 3 Changed", "Contacts", "Contact custom field 3 changed.", ["contact"], ["contact.u3_changed"]],
  ["contact.u4_changed", "Custom Field 4 Changed", "Contacts", "Contact custom field 4 changed.", ["contact"], ["contact.u4_changed"]],
  ["contact.u5_changed", "Custom Field 5 Changed", "Contacts", "Contact custom field 5 changed.", ["contact"], ["contact.u5_changed"]],
  ["contact.location_changed", "Contact Location Changed", "Contacts", "Contact map coordinates changed.", ["contact"], ["contact.location_changed"]],
  ["contact.converted_from_map_pin", "Created from Map Pin", "Contacts", "A contact was created from a map workflow.", ["contact"], ["contact.converted_from_map_pin"]],
  ["contact.created_from_schedule", "Created from Schedule", "Contacts", "A contact was created from scheduling.", ["contact"], ["contact.created_from_schedule"]],
  ["contact.created_manually", "Created Manually", "Contacts", "A contact was created manually in the app.", ["contact"], ["contact.created_manually"]],
  ["contact.imported_csv", "Imported from CSV", "Contacts", "A contact was imported from CSV.", ["contact"], ["contact.imported_csv"]],
  ["contact.imported_phone", "Imported from Phone Contacts", "Contacts", "A contact was imported from iOS Contacts.", ["contact"], ["contact.imported_phone"]],
  ["lead.created", "Lead Created", "Leads", "A new external lead was ingested.", ["contact"], ["lead.created"]],
  ["lead.created_manual", "Manual Lead Created", "Leads", "A lead was manually created.", ["contact"], ["lead.created_manual"]],
  ["lead.received_external", "External Lead Received", "Leads", "A lead was received from an external source.", ["contact"], ["lead.received_external"]],
  ["lead.received_zapier", "Lead Received from Zapier", "Leads", "A lead was received from Zapier.", ["contact"], ["lead.received_zapier"]],
  ["lead.received_meta", "Lead Received from Meta", "Leads", "A Meta/Facebook lead was received.", ["contact"], ["lead.received_meta"]],
  ["lead.received_website", "Lead Received from Website", "Leads", "A website lead was received.", ["contact"], ["lead.received_website"]],
  ["lead.received_webhook", "Lead Received from Webhook", "Leads", "A webhook lead was received.", ["contact"], ["lead.received_webhook"]],
  ["lead.imported", "Lead Imported", "Leads", "A lead was imported.", ["contact"], ["lead.imported"]],
  ["lead.assigned", "Lead Assigned", "Leads", "A lead was assigned where supported.", ["contact"], ["lead.assigned"]],
  ["lead.reassigned", "Lead Reassigned", "Leads", "A lead assignment changed where supported.", ["contact"], ["lead.reassigned"]],
  ["lead.source_changed", "Lead Source Changed", "Leads", "A lead source changed.", ["contact"], ["lead.source_changed"]],
  ["lead.external_form_received", "External Form Received", "Leads", "An external lead form was received.", ["contact"], ["lead.external_form_received"]],
  ["pipeline.opportunity_created", "Opportunity Created", "Pipeline", "A pipeline opportunity was created.", ["opportunity"], ["pipeline.opportunity_created"]],
  ["pipeline.opportunity_updated", "Opportunity Updated", "Pipeline", "A pipeline opportunity was updated.", ["opportunity"], ["pipeline.opportunity_updated"]],
  ["pipeline.stage_entered", "Stage Entered", "Pipeline", "An opportunity entered a pipeline stage.", ["opportunity"], ["pipeline.stage_entered"]],
  ["pipeline.stage_exited", "Stage Exited", "Pipeline", "An opportunity left a pipeline stage.", ["opportunity"], ["pipeline.stage_exited"]],
  ["pipeline.stage_changed", "Stage Changed", "Pipeline", "An opportunity changed stages.", ["opportunity"], ["pipeline.stage_changed"]],
  ["pipeline.opportunity_moved", "Opportunity Moved", "Pipeline", "An opportunity moved in the pipeline.", ["opportunity"], ["pipeline.opportunity_moved"]],
  ["pipeline.opportunity_removed", "Opportunity Removed", "Pipeline", "A contact was removed from the active pipeline.", ["opportunity"], ["pipeline.opportunity_removed"]],
  ["pipeline.won", "Opportunity Won", "Pipeline", "An opportunity was marked sold/won.", ["opportunity"], ["pipeline.won"]],
  ["pipeline.lost", "Opportunity Lost", "Pipeline", "An opportunity was marked lost.", ["opportunity"], ["pipeline.lost"]],
  ["pipeline.reopened", "Opportunity Reopened", "Pipeline", "A won/lost opportunity was reopened.", ["opportunity"], ["pipeline.reopened"]],
  ["pipeline.value_changed", "Opportunity Value Changed", "Pipeline", "The contact value for an opportunity changed.", ["opportunity"], ["pipeline.value_changed"]],
  ["pipeline.salesperson_assigned", "Salesperson Assigned", "Pipeline", "A salesperson was assigned where supported.", ["opportunity"], ["pipeline.salesperson_assigned"]],
  ["pipeline.salesperson_changed", "Salesperson Changed", "Pipeline", "A salesperson assignment changed where supported.", ["opportunity"], ["pipeline.salesperson_changed"]],
  ["pipeline.salesperson_removed", "Salesperson Removed", "Pipeline", "A salesperson was removed where supported.", ["opportunity"], ["pipeline.salesperson_removed"]],
  ["pipeline.reminder_created", "Pipeline Reminder Created", "Pipeline", "A follow-up reminder was created.", ["opportunity", "contact"], ["pipeline.reminder_created"]],
  ["pipeline.reminder_due", "Pipeline Reminder Due", "Pipeline", "A follow-up reminder is due.", ["opportunity", "contact"], ["pipeline.reminder_due"]],
  ["pipeline.reminder_completed", "Pipeline Reminder Completed", "Pipeline", "A follow-up reminder was completed.", ["opportunity", "contact"], ["pipeline.reminder_completed"]],
  ["pipeline.reminder_archived", "Pipeline Reminder Archived", "Pipeline", "A follow-up reminder was archived.", ["opportunity", "contact"], ["pipeline.reminder_archived"]],
  ["job.created", "Job Created", "Schedule", "A scheduled job was created.", ["job"], ["job.created"]],
  ["job.updated", "Job Updated", "Schedule", "A scheduled job was updated.", ["job"], ["job.updated"]],
  ["job.deleted", "Job Deleted", "Schedule & Jobs", "A job was deleted.", ["job"], ["job.deleted"]],
  ["job.restored", "Job Restored", "Schedule & Jobs", "Reserved for future server-side deleted job restore support.", ["job"], ["job.restored"]],
  ["job.scheduled", "Job Scheduled", "Schedule & Jobs", "A job received its initial scheduled start/end.", ["job"], ["job.scheduled"]],
  ["job.rescheduled", "Job Rescheduled", "Schedule & Jobs", "A job start or end time changed.", ["job"], ["job.rescheduled"]],
  ["job.canceled", "Job Canceled", "Schedule & Jobs", "Reserved for future server-side cancellation status.", ["job"], ["job.canceled"]],
  ["job.started", "Job Started", "Schedule & Jobs", "Reserved for future explicit job start status.", ["job"], ["job.started"]],
  ["job.start_time_reached", "Job Start Time Reached", "Schedule & Jobs", "The scheduled job start time was reached.", ["job"], ["job.start_time_reached"]],
  ["job.completed", "Job Completed", "Schedule", "A scheduled job was marked complete.", ["job"], ["job.completed"]],
  ["job.reopened", "Job Reopened", "Schedule & Jobs", "A completed job was reopened.", ["job"], ["job.reopened"]],
  ["job.overdue", "Job Overdue", "Schedule & Jobs", "A job end time passed without completion.", ["job"], ["job.overdue"]],
  ["job.relative_time", "Relative Job Time", "Schedule & Jobs", "Fires before or after a job start/end time.", ["job"], ["job.relative_time"]],
  ["job.field_changed", "Job Field Changed", "Schedule & Jobs", "A selected job field changed.", ["job"], ["job.field_changed"]],
  ["job.start_changed", "Job Start Changed", "Schedule & Jobs", "A job start time changed.", ["job"], ["job.start_changed"]],
  ["job.end_changed", "Job End Changed", "Schedule & Jobs", "A job end time changed.", ["job"], ["job.end_changed"]],
  ["job.date_changed", "Job Date Changed", "Schedule & Jobs", "A job date changed.", ["job"], ["job.date_changed"]],
  ["job.price_changed", "Job Price Changed", "Schedule & Jobs", "A job price changed.", ["job"], ["job.price_changed"]],
  ["job.material_cost_changed", "Material Cost Changed", "Schedule & Jobs", "A job material cost changed.", ["job"], ["job.material_cost_changed"]],
  ["job.color_changed", "Job Color Changed", "Schedule & Jobs", "A job color changed.", ["job"], ["job.color_changed"]],
  ["job.contact_changed", "Job Contact Changed", "Schedule & Jobs", "A job linked contact changed.", ["job"], ["job.contact_changed"]],
  ["job.service_added", "Job Service Added", "Schedule & Jobs", "A service was added to a job.", ["job"], ["job.service_added"]],
  ["job.service_removed", "Job Service Removed", "Schedule & Jobs", "A service was removed from a job.", ["job"], ["job.service_removed"]],
  ["job.services_changed", "Job Services Changed", "Schedule & Jobs", "A job service list changed.", ["job"], ["job.services_changed"]],
  ["job.worker_assigned", "Worker Assigned to Job", "Schedule & Jobs", "A worker was assigned to a job.", ["job"], ["job.worker_assigned"]],
  ["job.worker_removed", "Worker Removed from Job", "Schedule & Jobs", "A worker was removed from a job.", ["job"], ["job.worker_removed"]],
  ["job.workers_changed", "Job Workers Changed", "Schedule & Jobs", "A job worker list changed.", ["job"], ["job.workers_changed"]],
  ["job.salesperson_assigned", "Salesperson Assigned to Job", "Schedule & Jobs", "A salesperson was assigned to a job.", ["job"], ["job.salesperson_assigned"]],
  ["job.salesperson_removed", "Salesperson Removed from Job", "Schedule & Jobs", "A salesperson was removed from a job.", ["job"], ["job.salesperson_removed"]],
  ["job.salespeople_changed", "Job Salespeople Changed", "Schedule & Jobs", "A job salesperson list changed.", ["job"], ["job.salespeople_changed"]],
  ["job.first_job_for_contact", "First Job for Contact", "Schedule & Jobs", "A contact received their first job.", ["job"], ["job.first_job_for_contact"]],
  ["job.repeat_job_for_contact", "Repeat Job for Contact", "Schedule & Jobs", "A contact received a repeat job.", ["job"], ["job.repeat_job_for_contact"]],
  ["job.created_from_contact", "Job Created from Contact", "Schedule & Jobs", "A job was created from contact context.", ["job"], ["job.created_from_contact"]],
  ["job.created_from_map", "Job Created from Map", "Schedule & Jobs", "A job was created from map context.", ["job"], ["job.created_from_map"]],
  ["job.created_manually", "Job Created Manually", "Schedule & Jobs", "A job was manually created.", ["job"], ["job.created_manually"]],
  ["job.created_by_automation", "Job Created by Automation", "Schedule & Jobs", "A job was created by an automation action.", ["job"], ["job.created_by_automation"]],
  ["sms.received", "SMS Received", "Phone", "An inbound SMS/MMS was received.", ["sms_conversation", "contact"], ["sms.received"]],
  ["sms.sent", "SMS Sent", "Phone", "An SMS/MMS was sent.", ["sms_conversation", "contact"], ["sms.sent"]],
  ["sms.delivered", "SMS Delivered", "Cellular Messaging", "Twilio reported an outbound message delivered.", ["sms_message", "sms_conversation", "contact"], ["sms.delivered"]],
  ["sms.failed", "SMS Failed", "Cellular Messaging", "Twilio reported an outbound message failed.", ["sms_message", "sms_conversation", "contact"], ["sms.failed"]],
  ["sms.undelivered", "SMS Undelivered", "Cellular Messaging", "Twilio reported an outbound message undelivered.", ["sms_message", "sms_conversation", "contact"], ["sms.undelivered"]],
  ["sms.queued", "SMS Queued", "Cellular Messaging", "Twilio reported a message queued.", ["sms_message", "sms_conversation", "contact"], ["sms.queued"]],
  ["sms.sending", "SMS Sending", "Cellular Messaging", "Twilio reported a message sending.", ["sms_message", "sms_conversation", "contact"], ["sms.sending"]],
  ["sms.conversation_created", "SMS Conversation Created", "Cellular Messaging", "A customer SMS conversation was created.", ["sms_conversation"], ["sms.conversation_created"]],
  ["sms.conversation_read", "SMS Conversation Read", "Cellular Messaging", "A conversation was marked read.", ["sms_conversation"], ["sms.conversation_read"]],
  ["sms.conversation_unread", "SMS Conversation Unread", "Cellular Messaging", "A conversation became unread from inbound activity.", ["sms_conversation"], ["sms.conversation_unread"]],
  ["sms.reply_received", "Customer Reply Received", "Cellular Messaging", "An inbound message arrived after a prior outbound message.", ["sms_conversation", "contact"], ["sms.reply_received"]],
  ["sms.first_inbound", "First Inbound SMS", "Cellular Messaging", "The first inbound message in a conversation was received.", ["sms_conversation", "contact"], ["sms.first_inbound"]],
  ["sms.first_outbound", "First Outbound SMS", "Cellular Messaging", "The first outbound message in a conversation was sent.", ["sms_conversation", "contact"], ["sms.first_outbound"]],
  ["sms.first_message_from_number", "First Message From Number", "Cellular Messaging", "The first message from a phone number was received.", ["sms_conversation"], ["sms.first_message_from_number"]],
  ["sms.message_received_from_unknown_number", "SMS From Unknown Number", "Cellular Messaging", "An inbound SMS could not be matched to a contact.", ["sms_conversation"], ["sms.message_received_from_unknown_number"]],
  ["sms.message_received_from_contact", "SMS From Contact", "Cellular Messaging", "An inbound SMS matched a contact.", ["sms_conversation", "contact"], ["sms.message_received_from_contact"]],
  ["sms.keyword_received", "SMS Keyword Received", "Cellular Messaging", "An inbound SMS matched configured words or phrases.", ["sms_conversation", "contact"], ["sms.keyword_received"]],
  ["sms.attachment_received", "SMS Attachment Received", "Cellular Messaging", "An inbound SMS/MMS had media.", ["sms_conversation", "contact"], ["sms.attachment_received"]],
  ["sms.mms_received", "MMS Received", "Cellular Messaging", "An inbound MMS was received.", ["sms_conversation", "contact"], ["sms.mms_received"]],
  ["sms.mms_sent", "MMS Sent", "Cellular Messaging", "An outbound MMS was sent.", ["sms_message", "sms_conversation", "contact"], ["sms.mms_sent"]],
  ["sms.no_reply", "No Customer Reply", "Cellular Messaging", "A customer did not reply within a configured duration.", ["sms_conversation", "contact"], ["sms.no_reply"]],
  ["sms.conversation_inactive", "SMS Conversation Inactive", "Cellular Messaging", "A conversation had no new messages for a configured duration.", ["sms_conversation", "contact"], ["sms.conversation_inactive"]],
  ["call.missed", "Missed Call", "Phone", "An inbound call was missed.", ["call"], ["call.missed"]],
  ["call.incoming", "Incoming Call", "Calls", "An inbound call was received.", ["call"], ["call.incoming"]],
  ["call.outgoing", "Outgoing Call", "Calls", "An outbound call was started.", ["call"], ["call.outgoing"]],
  ["call.started", "Call Started", "Calls", "A call record was started.", ["call"], ["call.started"]],
  ["call.ringing", "Call Ringing", "Calls", "Twilio reported ringing.", ["call"], ["call.ringing"]],
  ["call.answered", "Call Answered", "Calls", "A call was answered.", ["call"], ["call.answered"]],
  ["call.connected", "Call Connected", "Calls", "A call connected/in-progress.", ["call"], ["call.connected"]],
  ["call.completed", "Call Completed", "Calls", "A logical call completed.", ["call"], ["call.completed"]],
  ["call.declined", "Call Declined", "Calls", "CallKit/Twilio reported a declined/canceled inbound call where distinguishable.", ["call"], ["call.declined"]],
  ["call.busy", "Call Busy", "Calls", "Twilio reported busy.", ["call"], ["call.busy"]],
  ["call.no_answer", "Call No Answer", "Calls", "Twilio reported no answer.", ["call"], ["call.no_answer"]],
  ["call.failed", "Call Failed", "Calls", "Twilio reported call failure.", ["call"], ["call.failed"]],
  ["call.short_call", "Short Call", "Calls", "A completed call duration was below threshold.", ["call"], ["call.short_call"]],
  ["call.long_call", "Long Call", "Calls", "A completed call duration exceeded threshold.", ["call"], ["call.long_call"]],
  ["call.first_call_with_contact", "First Call With Contact", "Calls", "The first logical call with a contact/number occurred.", ["call"], ["call.first_call_with_contact"]],
  ["call.after_hours", "After-Hours Call", "Calls", "An inbound call arrived outside business hours.", ["call"], ["call.after_hours"]],
  ["voicemail.received", "Voicemail Received", "Phone", "A voicemail recording was received.", ["voicemail"], ["voicemail.received"]],
  ["voicemail.recording_ready", "Voicemail Recording Ready", "Voicemail", "A voicemail recording is available.", ["voicemail"], ["voicemail.recording_ready"]],
  ["voicemail.read", "Voicemail Read", "Voicemail", "A voicemail was marked read.", ["voicemail"], ["voicemail.read"]],
  ["voicemail.unread", "Voicemail Unread", "Voicemail", "A voicemail was marked unread.", ["voicemail"], ["voicemail.unread"]],
  ["voicemail.deleted", "Voicemail Deleted", "Voicemail", "A WolfCRM voicemail record was deleted.", ["voicemail"], ["voicemail.deleted"]],
  ["voicemail.unread_for", "Voicemail Unread For", "Voicemail", "A voicemail remained unread for a configured duration.", ["voicemail"], ["voicemail.unread_for"]],
  ["voicemail.from_contact", "Voicemail From Contact", "Voicemail", "A voicemail matched a contact.", ["voicemail", "contact"], ["voicemail.from_contact"]],
  ["voicemail.from_unknown_number", "Voicemail From Unknown Number", "Voicemail", "A voicemail could not be matched to a contact.", ["voicemail"], ["voicemail.from_unknown_number"]],
  ["internal.message_received", "Internal Message Received", "Company Comms", "A company internal message was received.", ["internal_message"], ["internal.message_received"]],
  ["internal.message_sent", "Internal Message Sent", "Company Comms", "A company internal message was sent.", ["internal_message"], ["internal.message_sent"]],
  ["internal.dm_received", "DM Received", "Company Comms", "A direct internal message was received.", ["internal_message"], ["internal.dm_received"]],
  ["internal.group_message_received", "Group Message Received", "Company Comms", "A group conversation message was received.", ["internal_message"], ["internal.group_message_received"]],
  ["internal.channel_message_received", "Channel Message Received", "Company Comms", "A channel message was posted.", ["internal_message", "channel"], ["internal.channel_message_received"]],
  ["internal.attachment_received", "Internal Attachment Received", "Company Comms", "An internal message included attachments.", ["internal_message"], ["internal.attachment_received"]],
  ["internal.conversation_created", "Conversation Created", "Company Comms", "An internal conversation was created.", ["internal_conversation"], ["internal.conversation_created"]],
  ["internal.group_created", "Group Created", "Company Comms", "An internal group conversation was created.", ["internal_conversation"], ["internal.group_created"]],
  ["internal.channel_created", "Channel Created", "Company Comms", "A channel was created.", ["channel"], ["internal.channel_created"]],
  ["internal.channel_deleted", "Channel Deleted", "Company Comms", "A channel was archived/deleted.", ["channel"], ["internal.channel_deleted"]],
  ["internal.message_deleted", "Internal Message Deleted", "Company Comms", "An internal message was deleted.", ["internal_message"], ["internal.message_deleted"]],
  ["internal.conversation_read", "Internal Conversation Read", "Company Comms", "An internal conversation was marked read.", ["internal_conversation"], ["internal.conversation_read"]],
  ["internal.conversation_unread", "Internal Conversation Unread", "Company Comms", "An internal conversation became unread.", ["internal_conversation"], ["internal.conversation_unread"]],
  ["quote.created", "Quote Created", "Quotes", "A quote was created.", ["quote", "contact"], ["quote.created"]],
  ["quote.updated", "Quote Updated", "Quotes", "A quote was updated.", ["quote", "contact"], ["quote.updated"]],
  ["quote.deleted", "Quote Deleted", "Quotes", "A quote was deleted.", ["quote", "contact"], ["quote.deleted"]],
  ["quote.line_item_added", "Quote Line Item Added", "Quotes", "A quote line item was added.", ["quote"], ["quote.line_item_added"]],
  ["quote.line_item_removed", "Quote Line Item Removed", "Quotes", "A quote line item was removed.", ["quote"], ["quote.line_item_removed"]],
  ["quote.line_items_changed", "Quote Line Items Changed", "Quotes", "Quote line items changed.", ["quote"], ["quote.line_items_changed"]],
  ["quote.total_changed", "Quote Total Changed", "Quotes", "A quote total changed.", ["quote"], ["quote.total_changed"]],
  ["quote.contact_changed", "Quote Contact Changed", "Quotes", "A quote contact changed.", ["quote", "contact"], ["quote.contact_changed"]],
  ["quote.status_changed", "Quote Status Changed", "Quotes", "A quote lifecycle status changed.", ["quote"], ["quote.status_changed"]],
  ["quote.sent", "Quote Sent", "Quotes", "A quote was marked sent.", ["quote"], ["quote.sent"]],
  ["quote.accepted", "Quote Accepted", "Quotes", "A quote was marked accepted.", ["quote"], ["quote.accepted"]],
  ["quote.declined", "Quote Declined", "Quotes", "A quote was marked declined.", ["quote"], ["quote.declined"]],
  ["quote.expired", "Quote Expired", "Quotes", "A quote expiration date was reached.", ["quote"], ["quote.expired"]],
  ["quote.converted_to_job", "Quote Converted to Job", "Quotes", "A quote was converted into a scheduled job.", ["quote", "job"], ["quote.converted_to_job"]],
  ["quote.scheduled", "Quote Scheduled", "Quotes", "A quote produced a scheduled job.", ["quote", "job"], ["quote.scheduled"]],
  ["quote.followup_due", "Quote Follow-Up Due", "Quotes", "A quote follow-up timer became due.", ["quote"], ["quote.followup_due"]],
  ["invoice.created", "Invoice Created", "Invoices", "A durable invoice record was created.", ["invoice", "contact"], ["invoice.created"]],
  ["invoice.issued", "Invoice Issued", "Invoices", "An invoice was issued.", ["invoice"], ["invoice.issued"]],
  ["invoice.updated", "Invoice Updated", "Invoices", "An invoice was updated.", ["invoice"], ["invoice.updated"]],
  ["invoice.due", "Invoice Due", "Invoices", "An invoice due date arrived.", ["invoice"], ["invoice.due"]],
  ["invoice.overdue", "Invoice Overdue", "Invoices", "An unpaid invoice became overdue.", ["invoice"], ["invoice.overdue"]],
  ["invoice.paid", "Invoice Paid", "Invoices", "An invoice was paid.", ["invoice", "payment"], ["invoice.paid"]],
  ["invoice.voided", "Invoice Voided", "Invoices", "An invoice was voided.", ["invoice"], ["invoice.voided"]],
  ["invoice.deleted", "Invoice Deleted", "Invoices", "An invoice record was deleted.", ["invoice"], ["invoice.deleted"]],
  ["invoice.total_changed", "Invoice Total Changed", "Invoices", "An invoice total changed.", ["invoice"], ["invoice.total_changed"]],
  ["payment.created", "Payment Created", "Payments", "A payment record was created.", ["payment", "contact"], ["payment.created"]],
  ["payment.started", "Payment Started", "Payments", "A payment collection flow started.", ["payment", "contact"], ["payment.started"]],
  ["payment.pending", "Payment Pending", "Payments", "A payment is pending.", ["payment", "contact"], ["payment.pending"]],
  ["payment.succeeded", "Payment Succeeded", "Payments", "A Stripe payment succeeded.", ["payment", "contact"], ["payment.succeeded"]],
  ["payment.failed", "Payment Failed", "Payments", "A Stripe payment failed.", ["payment", "contact"], ["payment.failed"]],
  ["payment.canceled", "Payment Canceled", "Payments", "A payment was canceled.", ["payment"], ["payment.canceled"]],
  ["payment.refunded", "Payment Refunded", "Payments", "A payment was refunded.", ["payment"], ["payment.refunded"]],
  ["payment.partially_refunded", "Payment Partially Refunded", "Payments", "A payment was partially refunded.", ["payment"], ["payment.partially_refunded"]],
  ["payment.payment_method_required", "Payment Method Required", "Payments", "Stripe requires a payment method.", ["payment"], ["payment.payment_method_required"]],
  ["payment.action_required", "Payment Action Required", "Payments", "Stripe requires customer action.", ["payment"], ["payment.action_required"]],
  ["payment.dispute_created", "Payment Dispute Created", "Payments", "A Stripe dispute was created.", ["payment"], ["payment.dispute_created"]],
  ["payment.dispute_updated", "Payment Dispute Updated", "Payments", "A Stripe dispute changed.", ["payment"], ["payment.dispute_updated"]],
  ["payment.dispute_closed", "Payment Dispute Closed", "Payments", "A Stripe dispute closed.", ["payment"], ["payment.dispute_closed"]],
  ["service_plan.created", "Service Plan Created", "Service Plans", "A service plan was created.", ["service_plan"], ["service_plan.created"]],
  ["service_plan.updated", "Service Plan Updated", "Service Plans", "A service plan was updated.", ["service_plan"], ["service_plan.updated"]],
  ["service_plan.activated", "Service Plan Activated", "Service Plans", "A service plan became active.", ["service_plan"], ["service_plan.activated"]],
  ["service_plan.paused", "Service Plan Paused", "Service Plans", "A service plan was paused.", ["service_plan"], ["service_plan.paused"]],
  ["service_plan.resumed", "Service Plan Resumed", "Service Plans", "A service plan resumed.", ["service_plan"], ["service_plan.resumed"]],
  ["service_plan.canceled", "Service Plan Canceled", "Service Plans", "A service plan was canceled.", ["service_plan"], ["service_plan.canceled"]],
  ["service_plan.serviced", "Service Plan Serviced", "Service Plans", "A service plan was marked serviced.", ["service_plan"], ["service_plan.serviced"]],
  ["service_plan.service_due", "Service Due", "Service Plans", "A service plan service date arrived.", ["service_plan"], ["service_plan.service_due"]],
  ["service_plan.service_upcoming", "Service Upcoming", "Service Plans", "A service plan service date is approaching.", ["service_plan"], ["service_plan.service_upcoming"]],
  ["service_plan.service_overdue", "Service Overdue", "Service Plans", "A service plan service became overdue.", ["service_plan"], ["service_plan.service_overdue"]],
  ["service_plan.next_service_changed", "Next Service Changed", "Service Plans", "The next service date changed.", ["service_plan"], ["service_plan.next_service_changed"]],
  ["service_plan.price_changed", "Service Plan Price Changed", "Service Plans", "A service plan price changed.", ["service_plan"], ["service_plan.price_changed"]],
  ["service_plan.billing_interval_changed", "Billing Interval Changed", "Service Plans", "A billing interval changed.", ["service_plan"], ["service_plan.billing_interval_changed"]],
  ["service_plan.service_interval_changed", "Service Interval Changed", "Service Plans", "A service interval changed.", ["service_plan"], ["service_plan.service_interval_changed"]],
  ["service_plan.first_service_date_changed", "First Service Date Changed", "Service Plans", "A first service date changed.", ["service_plan"], ["service_plan.first_service_date_changed"]],
  ["service_plan.subscription_created", "Subscription Created", "Subscriptions", "A Stripe subscription was created.", ["service_plan"], ["service_plan.subscription_created"]],
  ["service_plan.subscription_active", "Subscription Active", "Subscriptions", "A subscription became active.", ["service_plan"], ["service_plan.subscription_active"]],
  ["service_plan.subscription_paused", "Subscription Paused", "Subscriptions", "A subscription paused where supported by Stripe.", ["service_plan"], ["service_plan.subscription_paused"]],
  ["service_plan.subscription_canceled", "Subscription Canceled", "Subscriptions", "A subscription was canceled.", ["service_plan"], ["service_plan.subscription_canceled"]],
  ["service_plan.subscription_payment_succeeded", "Subscription Payment Succeeded", "Subscriptions", "A service-plan subscription payment succeeded.", ["service_plan", "payment"], ["service_plan.subscription_payment_succeeded"]],
  ["service_plan.subscription_payment_failed", "Subscription Payment Failed", "Subscriptions", "A service-plan subscription payment failed.", ["service_plan", "payment"], ["service_plan.subscription_payment_failed"]],
  ["service_plan.subscription_past_due", "Subscription Past Due", "Subscriptions", "A subscription became past due.", ["service_plan"], ["service_plan.subscription_past_due"]],
  ["service_plan.subscription_unpaid", "Subscription Unpaid", "Subscriptions", "A subscription became unpaid.", ["service_plan"], ["service_plan.subscription_unpaid"]],
  ["service_plan.subscription_trial_ending", "Subscription Trial Ending", "Subscriptions", "Stripe reported a subscription trial ending.", ["service_plan"], ["service_plan.subscription_trial_ending"]],
  ["map.pin_created", "Map Pin Created", "Map & Canvassing", "A field map pin was created.", ["map_pin"], ["map.pin_created"]],
  ["map.pin_updated", "Map Pin Updated", "Map & Canvassing", "A field map pin was updated.", ["map_pin"], ["map.pin_updated"]],
  ["map.pin_deleted", "Map Pin Deleted", "Map & Canvassing", "A field map pin was deleted.", ["map_pin"], ["map.pin_deleted"]],
  ["map.pin_status_changed", "Pin Status Changed", "Map & Canvassing", "A map pin changed status.", ["map_pin"], ["map.pin_status_changed"]],
  ["map.pin_list_changed", "Pin List Changed", "Map & Canvassing", "A map pin moved between durable lists.", ["map_pin"], ["map.pin_list_changed"]],
  ["map.pin_added_to_list", "Pin Added to List", "Map & Canvassing", "A map pin was added to a durable list.", ["map_pin"], ["map.pin_added_to_list"]],
  ["map.pin_removed_from_list", "Pin Removed from List", "Map & Canvassing", "A map pin was removed from a durable list.", ["map_pin"], ["map.pin_removed_from_list"]],
  ["map.pin_contact_linked", "Pin Contact Linked", "Map & Canvassing", "A contact was linked to a pin.", ["map_pin", "contact"], ["map.pin_contact_linked"]],
  ["map.pin_contact_unlinked", "Pin Contact Unlinked", "Map & Canvassing", "A contact was unlinked from a pin.", ["map_pin"], ["map.pin_contact_unlinked"]],
  ["map.pin_address_changed", "Pin Address Changed", "Map & Canvassing", "A map pin address changed.", ["map_pin"], ["map.pin_address_changed"]],
  ["map.pin_location_changed", "Pin Location Changed", "Map & Canvassing", "A map pin coordinate changed.", ["map_pin"], ["map.pin_location_changed"]],
  ["map.pin_note_added", "Pin Note Added", "Map & Canvassing", "A field note was added to a map pin.", ["map_pin"], ["map.pin_note_added"]],
  ["map.pin_converted_to_contact", "Pin Converted to Contact", "Map & Canvassing", "A contact was created from a map pin.", ["map_pin", "contact"], ["map.pin_converted_to_contact"]],
  ["map.pin_converted_to_lead", "Pin Converted to Lead", "Map & Canvassing", "A map pin became a lead.", ["map_pin"], ["map.pin_converted_to_lead"]],
  ["map.pin_marked_won", "Pin Marked Won", "Map & Canvassing", "A map pin was marked won.", ["map_pin"], ["map.pin_marked_won"]],
  ["map.pin_marked_lost", "Pin Marked Lost", "Map & Canvassing", "A map pin was marked lost.", ["map_pin"], ["map.pin_marked_lost"]],
  ["map.pin_marked_reloop", "Pin Marked Reloop", "Map & Canvassing", "A map pin was marked for reloop.", ["map_pin"], ["map.pin_marked_reloop"]],
  ["map.pin_marked_later", "Pin Marked Later", "Map & Canvassing", "A map pin was marked later/no-answer.", ["map_pin"], ["map.pin_marked_later"]],
  ["map.pin_visited", "Pin Visited", "Map & Canvassing", "A field visit was recorded for a pin.", ["map_pin"], ["map.pin_visited"]],
  ["map.pin_knocked", "Pin Knock Recorded", "Map & Canvassing", "A door knock was recorded for a pin.", ["map_pin"], ["map.pin_knocked"]],
  ["map.pin_followup_due", "Pin Follow-Up Due", "Map & Canvassing", "A configured map follow-up became due.", ["map_pin"], ["map.pin_followup_due"]],
  ["canvass.knock_recorded", "Door Knock Recorded", "Map & Canvassing", "A door knock was recorded.", ["map_pin"], ["canvass.knock_recorded"]],
  ["canvass.outcome_recorded", "Canvass Outcome Recorded", "Map & Canvassing", "A door-knocking outcome was recorded.", ["map_pin"], ["canvass.outcome_recorded"]],
  ["canvass.lead_created", "Canvass Lead Created", "Map & Canvassing", "A canvassing pin became a lead.", ["map_pin"], ["canvass.lead_created"]],
  ["canvass.reloop_created", "Canvass Reloop Created", "Map & Canvassing", "A canvassing pin was marked for reloop.", ["map_pin"], ["canvass.reloop_created"]],
  ["canvass.no_answer", "Canvass No Answer", "Map & Canvassing", "A canvassing pin was marked later/no-answer.", ["map_pin"], ["canvass.no_answer"]],
  ["canvass.not_interested", "Canvass Not Interested", "Map & Canvassing", "A canvassing pin was marked lost/not interested.", ["map_pin"], ["canvass.not_interested"]],
  ["canvass.sale_recorded", "Canvass Sale Recorded", "Map & Canvassing", "A canvassing pin was marked won.", ["map_pin"], ["canvass.sale_recorded"]],
  ["route.created", "Route Created", "Routes", "A field route was created.", ["route"], ["route.created"]],
  ["route.updated", "Route Updated", "Routes", "A field route was updated.", ["route"], ["route.updated"]],
  ["route.deleted", "Route Deleted", "Routes", "A field route was deleted.", ["route"], ["route.deleted"]],
  ["route.stop_added", "Route Stop Added", "Routes", "A stop was added to a field route.", ["route", "route_stop"], ["route.stop_added"]],
  ["route.stop_removed", "Route Stop Removed", "Routes", "A stop was removed from a field route.", ["route", "route_stop"], ["route.stop_removed"]],
  ["route.reordered", "Route Reordered", "Routes", "Route stop order changed.", ["route"], ["route.reordered"]],
  ["route.assigned", "Route Assigned", "Routes", "A route was assigned to a rep.", ["route", "employee"], ["route.assigned"]],
  ["route.started", "Route Started", "Routes", "A field route was marked started.", ["route"], ["route.started"]],
  ["route.completed", "Route Completed", "Routes", "A field route was completed.", ["route"], ["route.completed"]],
  ["route.stop_completed", "Route Stop Completed", "Routes", "A route stop was completed.", ["route_stop"], ["route.stop_completed"]],
  ["route.stop_skipped", "Route Stop Skipped", "Routes", "A route stop was skipped.", ["route_stop"], ["route.stop_skipped"]],
  ["route.all_stops_completed", "All Route Stops Completed", "Routes", "Every route stop reached a terminal state.", ["route"], ["route.all_stops_completed"]],
  ["route.scheduled", "Route Scheduled", "Routes", "A route was scheduled for a date.", ["route"], ["route.scheduled"]],
  ["employee.created", "Employee Created", "Employees & Team", "An employee account was created.", ["employee"], ["employee.created"]],
  ["employee.invited", "Employee Invited", "Employees & Team", "An employee invite/account was created.", ["employee"], ["employee.invited"]],
  ["employee.joined", "Employee Joined", "Employees & Team", "An employee joined the company.", ["employee"], ["employee.joined"]],
  ["employee.updated", "Employee Updated", "Employees & Team", "An employee profile changed.", ["employee"], ["employee.updated"]],
  ["employee.role_changed", "Employee Role Changed", "Employees & Team", "An employee role changed.", ["employee"], ["employee.role_changed"]],
  ["employee.deactivated", "Employee Deactivated", "Employees & Team", "An employee was deactivated/removed.", ["employee"], ["employee.deactivated"]],
  ["employee.reactivated", "Employee Reactivated", "Employees & Team", "An employee was restored.", ["employee"], ["employee.reactivated"]],
  ["employee.removed", "Employee Removed", "Employees & Team", "An employee was removed from active access.", ["employee"], ["employee.removed"]],
  ["employee.permission_changed", "Employee Permission Changed", "Employees & Team", "A persisted employee permission changed.", ["employee"], ["employee.permission_changed"]],
  ["time_clock.clocked_in", "Employee Clocked In", "Time Clock", "An employee clocked in.", ["time_entry", "employee"], ["time_clock.clocked_in"]],
  ["time_clock.clocked_out", "Employee Clocked Out", "Time Clock", "An employee clocked out.", ["time_entry", "employee"], ["time_clock.clocked_out"]],
  ["time_clock.shift_started", "Shift Started", "Time Clock", "A time-clock shift started.", ["time_entry", "employee"], ["time_clock.shift_started"]],
  ["time_clock.shift_completed", "Shift Completed", "Time Clock", "A time-clock shift completed.", ["time_entry", "employee"], ["time_clock.shift_completed"]],
  ["time_clock.shift_updated", "Shift Updated", "Time Clock", "A time-clock entry changed.", ["time_entry"], ["time_clock.shift_updated"]],
  ["time_clock.manual_edit", "Time Entry Manual Edit", "Time Clock", "A time-clock entry was manually edited.", ["time_entry"], ["time_clock.manual_edit"]],
  ["time_clock.break_started", "Break Started", "Time Clock", "An employee started a break.", ["time_entry", "employee"], ["time_clock.break_started"]],
  ["time_clock.break_ended", "Break Ended", "Time Clock", "An employee ended a break.", ["time_entry", "employee"], ["time_clock.break_ended"]],
  ["time_clock.shift_duration_reached", "Shift Duration Reached", "Time Clock", "An active shift reached a configured duration.", ["time_entry", "employee"], ["time_clock.shift_duration_reached"]],
  ["time_clock.overtime_threshold_reached", "Overtime Threshold Reached", "Time Clock", "A configured operational overtime threshold was reached.", ["time_entry", "employee"], ["time_clock.overtime_threshold_reached"]],
  ["time_clock.missed_clock_out", "Missed Clock-Out", "Time Clock", "An employee remained clocked in past a configured threshold.", ["time_entry", "employee"], ["time_clock.missed_clock_out"]],
  ["measurement.created", "Measurement Created", "Measurements", "A property measurement was created.", ["measurement"], ["measurement.created"]],
  ["measurement.updated", "Measurement Updated", "Measurements", "A property measurement changed.", ["measurement"], ["measurement.updated"]],
  ["measurement.deleted", "Measurement Deleted", "Measurements", "A property measurement was deleted.", ["measurement"], ["measurement.deleted"]],
  ["measurement.completed", "Measurement Completed", "Measurements", "A measurement with enough points was saved.", ["measurement"], ["measurement.completed"]],
  ["measurement.area_changed", "Measurement Area Changed", "Measurements", "A measurement area changed.", ["measurement"], ["measurement.area_changed"]],
  ["measurement.distance_changed", "Measurement Distance Changed", "Measurements", "A measurement distance changed.", ["measurement"], ["measurement.distance_changed"]],
  ["measurement.linked_to_contact", "Measurement Linked to Contact", "Measurements", "A measurement was linked to a contact.", ["measurement", "contact"], ["measurement.linked_to_contact"]],
  ["measurement.linked_to_pin", "Measurement Linked to Pin", "Measurements", "Reserved for future pin-linked measurements.", ["measurement", "map_pin"], ["measurement.linked_to_pin"]],
  ["task.created", "Task Created", "Tasks", "A task was created.", ["task"], ["task.created"]],
  ["task.updated", "Task Updated", "Tasks", "A task was updated.", ["task"], ["task.updated"]],
  ["task.assigned", "Task Assigned", "Tasks", "A task was assigned to a user.", ["task"], ["task.assigned"]],
  ["task.reassigned", "Task Reassigned", "Tasks", "A task assignee changed.", ["task"], ["task.reassigned"]],
  ["task.unassigned", "Task Unassigned", "Tasks", "A task was unassigned.", ["task"], ["task.unassigned"]],
  ["task.due", "Task Due", "Tasks", "A task due time was reached.", ["task"], ["task.due"]],
  ["task.overdue", "Task Overdue", "Tasks", "A task became overdue while incomplete.", ["task"], ["task.overdue"]],
  ["task.completed", "Task Completed", "Tasks", "A todo task was completed.", ["task"], ["task.completed"]],
  ["task.reopened", "Task Reopened", "Tasks", "A completed task was reopened.", ["task"], ["task.reopened"]],
  ["task.deleted", "Task Deleted", "Tasks", "A task was deleted.", ["task"], ["task.deleted"]],
  ["task.rescheduled", "Task Rescheduled", "Tasks", "A task due date changed.", ["task"], ["task.rescheduled"]],
  ["task.title_changed", "Task Title Changed", "Tasks", "A task title changed.", ["task"], ["task.title_changed"]],
  ["task.due_changed", "Task Due Changed", "Tasks", "A task due date changed.", ["task"], ["task.due_changed"]],
  ["task.contact_changed", "Task Contact Changed", "Tasks", "Reserved for future contact-linked server task support.", ["task"], ["task.contact_changed"]],
  ["task.subtask_added", "Subtask Added", "Tasks", "A subtask was added.", ["task"], ["task.subtask_added"]],
  ["task.subtask_completed", "Subtask Completed", "Tasks", "A subtask was completed.", ["task"], ["task.subtask_completed"]],
  ["task.all_subtasks_completed", "All Subtasks Completed", "Tasks", "All subtasks transitioned to completed.", ["task"], ["task.all_subtasks_completed"]],
  ["routine.created", "Routine Created", "Routines", "A routine was created.", ["routine"], ["routine.created"]],
  ["routine.updated", "Routine Updated", "Routines", "A routine was updated.", ["routine"], ["routine.updated"]],
  ["routine.due", "Routine Due", "Routines", "A routine occurrence is due.", ["routine"], ["routine.due"]],
  ["routine.completed", "Routine Completed", "Routines", "A routine occurrence was completed.", ["routine"], ["routine.completed"]],
  ["routine.missed", "Routine Missed", "Routines", "A routine occurrence was missed.", ["routine"], ["routine.missed"]],
  ["routine.ended", "Routine Ended", "Routines", "A routine was disabled or deleted.", ["routine"], ["routine.ended"]],
  ["routine.reactivated", "Routine Reactivated", "Routines", "A disabled routine was re-enabled.", ["routine"], ["routine.reactivated"]],
  ["routine.weekday_reached", "Routine Weekday Reached", "Routines", "A configured routine weekday was reached.", ["routine"], ["routine.weekday_reached"]],
  ["customer_reminder.created", "Customer Reminder Created", "Customer Reminders", "A customer reminder was created.", ["customer_reminder"], ["customer_reminder.created"]],
  ["customer_reminder.due", "Customer Reminder Due", "Customer Reminders", "A customer reminder due time was reached.", ["customer_reminder"], ["customer_reminder.due"]],
  ["customer_reminder.overdue", "Customer Reminder Overdue", "Customer Reminders", "A customer reminder became overdue.", ["customer_reminder"], ["customer_reminder.overdue"]],
  ["customer_reminder.completed", "Customer Reminder Completed", "Customer Reminders", "A customer reminder was completed.", ["customer_reminder"], ["customer_reminder.completed"]],
  ["customer_reminder.rescheduled", "Customer Reminder Rescheduled", "Customer Reminders", "A customer reminder due date changed.", ["customer_reminder"], ["customer_reminder.rescheduled"]],
  ["customer_reminder.deleted", "Customer Reminder Deleted", "Customer Reminders", "A customer reminder was deleted.", ["customer_reminder"], ["customer_reminder.deleted"]],
  ["customer_reminder.reopened", "Customer Reminder Reopened", "Customer Reminders", "A completed customer reminder was reopened.", ["customer_reminder"], ["customer_reminder.reopened"]]
].map(([key, displayName, category, description, subjectTypes, eventTypes]) => ({
  key,
  display_name: displayName,
  category,
  description,
  supported_subject_types: subjectTypes,
  event_types: eventTypes,
  config_fields: triggerConfigFields(key),
  outputs: ["default"],
  icon: triggerIcon(key),
  visibility: triggerVisibility(key),
  ...deprecationFor(key),
  wired: !["contact.restored", "contact.assigned", "contact.reassigned", "contact.unassigned", "lead.assigned", "lead.reassigned", "pipeline.salesperson_assigned", "pipeline.salesperson_changed", "pipeline.salesperson_removed", "job.restored", "job.canceled", "job.started", "call.declined", "internal.mention_received"].includes(key)
}));

const actionCatalog = [
  ["contact.create", "Create Contact", "Contacts", "Creates a company contact.", ["generic"], ["default"]],
  ["contact.delete", "Delete Contact", "Contacts", "Deletes a contact after explicit node confirmation.", ["contact"], ["default"]],
  ["contact.restore", "Restore Contact", "Contacts", "Reserved for future soft-delete restore support.", ["contact"], ["default"]],
  ["contact.add_tag", "Add Contact Tag", "Contacts", "Adds one or more tags without removing existing tags.", ["contact"], ["default"]],
  ["contact.remove_tag", "Remove Contact Tag", "Contacts", "Removes selected tags from a contact.", ["contact"], ["default"]],
  ["contact.replace_tags", "Replace Contact Tags", "Contacts", "Replaces all contact tags with a new list.", ["contact"], ["default"]],
  ["contact.clear_tags", "Clear Contact Tags", "Contacts", "Removes all tags from a contact.", ["contact"], ["default"]],
  ["contact.update_fields", "Update Contact Fields", "Contacts", "Updates whitelisted contact fields.", ["contact"], ["default"]],
  ["contact.assign_user", "Assign Contact User", "Contacts", "Deferred because contacts do not currently have an assignment column.", ["contact"], ["default"]],
  ["contact.unassign_user", "Unassign Contact User", "Contacts", "Deferred because contacts do not currently have an assignment column.", ["contact"], ["default"]],
  ["contact.set_source", "Set Contact Source", "Contacts", "Sets the contact source field.", ["contact"], ["default"]],
  ["contact.set_value", "Set Contact Value", "Contacts", "Sets the contact value.", ["contact"], ["default"]],
  ["contact.set_job_type", "Set Job Type", "Contacts", "Sets the contact job type.", ["contact"], ["default"]],
  ["contact.set_custom_field", "Set Custom Field", "Contacts", "Sets one of the five contact custom fields.", ["contact"], ["default"]],
  ["contact.set_location", "Set Contact Location", "Contacts", "Sets contact latitude/longitude.", ["contact"], ["default"]],
  ["contact.add_note", "Add Contact Note", "Contacts", "Adds a server-synced contact note/activity.", ["contact"], ["default"]],
  ["contact.add_activity", "Add Contact Activity", "Contacts", "Adds a server-synced contact activity entry.", ["contact"], ["default"]],
  ["contact.add_to_map", "Add Contact to Map", "Contacts", "Creates a map pin linked to the contact.", ["contact"], ["default"]],
  ["pipeline.create_opportunity", "Create Opportunity", "Pipeline", "Creates an active opportunity for a contact.", ["contact"], ["default"]],
  ["pipeline.move_stage", "Move Pipeline Stage", "Pipeline", "Moves the selected Contact's pipeline opportunity to a Stage. WolfCRM can create the opportunity if it does not exist.", ["contact", "opportunity"], ["default"]],
  ["pipeline.remove_opportunity", "Remove Opportunity", "Pipeline", "Removes a contact from the active pipeline.", ["contact", "opportunity"], ["default"]],
  ["pipeline.mark_won", "Mark Opportunity Won", "Pipeline", "Marks an opportunity sold/won.", ["contact", "opportunity"], ["default"]],
  ["pipeline.mark_lost", "Mark Opportunity Lost", "Pipeline", "Marks an opportunity lost.", ["contact", "opportunity"], ["default"]],
  ["pipeline.reopen", "Reopen Opportunity", "Pipeline", "Reopens a won/lost opportunity into a selected stage.", ["contact", "opportunity"], ["default"]],
  ["pipeline.set_value", "Set Opportunity Value", "Pipeline", "Sets the contact value used by the opportunity.", ["contact", "opportunity"], ["default"]],
  ["pipeline.assign_salesperson", "Assign Salesperson", "Pipeline", "Deferred: current opportunity model has no salesperson column.", ["opportunity"], ["default"]],
  ["pipeline.remove_salesperson", "Remove Salesperson", "Pipeline", "Deferred: current opportunity model has no salesperson column.", ["opportunity"], ["default"]],
  ["pipeline.create_reminder", "Create Pipeline Reminder", "Pipeline", "Creates a server-synced follow-up reminder.", ["contact", "opportunity"], ["default"]],
  ["pipeline.complete_reminder", "Complete Pipeline Reminder", "Pipeline", "Archives a follow-up reminder as completed.", ["contact", "opportunity"], ["default"]],
  ["pipeline.archive_reminder", "Archive Pipeline Reminder", "Pipeline", "Archives a follow-up reminder.", ["contact", "opportunity"], ["default"]],
  ["task.create", "Create Task", "Tasks", "Creates a todo task.", ["generic"], ["default"]],
  ["notification.send_push", "Send Push Notification", "Notifications", "Sends APNs push notifications to scoped company users.", ["generic"], ["default"]],
  ["sms.send", "Send SMS", "Phone", "Sends SMS to the selected Contact, SMS conversation, or phone number through the configured company phone line.", ["contact", "sms_conversation"], ["default"]],
  ["sms.send_mms", "Send MMS", "Cellular Messaging", "Sends MMS through the configured company phone line.", ["contact", "sms_conversation"], ["default"]],
  ["sms.mark_conversation_read", "Mark SMS Conversation Read", "Cellular Messaging", "Marks a cellular conversation read.", ["sms_conversation"], ["default"]],
  ["sms.mark_conversation_unread", "Mark SMS Conversation Unread", "Cellular Messaging", "Marks a cellular conversation unread.", ["sms_conversation"], ["default"]],
  ["sms.delete_local_message", "Delete Local SMS Message", "Cellular Messaging", "Deletes WolfCRM's local message copy.", ["sms_message"], ["default"]],
  ["sms.delete_local_conversation", "Delete Local SMS Conversation", "Cellular Messaging", "Deletes WolfCRM's local conversation copy.", ["sms_conversation"], ["default"]],
  ["phone.create_contact_from_number", "Create Contact from Phone Number", "Cellular Messaging", "Creates a contact from a communication phone number.", ["sms_conversation", "call", "voicemail"], ["default"]],
  ["internal.send_message", "Send Internal Message", "Company Comms", "Sends a message to a conversation or channel.", ["generic"], ["default"]],
  ["internal.send_dm", "Send DM", "Company Comms", "Sends a direct message as the company owner/system sender.", ["generic"], ["default"]],
  ["internal.send_group_message", "Send Group Message", "Company Comms", "Sends to an existing group conversation.", ["generic"], ["default"]],
  ["internal.send_channel_message", "Send Channel Message", "Company Comms", "Sends to an existing channel.", ["generic"], ["default"]],
  ["internal.create_group", "Create Group", "Company Comms", "Creates an internal group conversation.", ["generic"], ["default"]],
  ["internal.create_channel", "Create Channel", "Company Comms", "Creates a company channel.", ["generic"], ["default"]],
  ["internal.mark_conversation_read", "Mark Internal Conversation Read", "Company Comms", "Marks an internal conversation read for the automation sender.", ["internal_conversation"], ["default"]],
  ["call.set_disposition", "Set Call Disposition", "Calls", "Sets CRM disposition without changing Twilio status.", ["call"], ["default"]],
  ["call.create_callback_task", "Create Callback Task", "Calls", "Creates a callback task from a call.", ["call"], ["default"]],
  ["call.send_followup_sms", "Send Call Follow-Up SMS", "Calls", "Sends follow-up SMS using the shared SMS safety path.", ["call"], ["default"]],
  ["call.add_contact_note", "Add Call Contact Note", "Calls", "Adds a contact note related to the call.", ["call", "contact"], ["default"]],
  ["voicemail.mark_read", "Mark Voicemail Read", "Voicemail", "Marks a voicemail read.", ["voicemail"], ["default"]],
  ["voicemail.mark_unread", "Mark Voicemail Unread", "Voicemail", "Marks a voicemail unread.", ["voicemail"], ["default"]],
  ["voicemail.delete", "Delete Voicemail", "Voicemail", "Deletes the WolfCRM voicemail record.", ["voicemail"], ["default"]],
  ["voicemail.create_callback_task", "Create Voicemail Callback Task", "Voicemail", "Creates a callback task from voicemail.", ["voicemail"], ["default"]],
  ["voicemail.send_followup_sms", "Send Voicemail Follow-Up SMS", "Voicemail", "Sends follow-up SMS using the shared SMS safety path.", ["voicemail"], ["default"]],
  ["quote.create", "Create Quote", "Quotes", "Creates a contact quote with line items.", ["contact"], ["default"]],
  ["quote.update", "Update Quote", "Quotes", "Updates quote fields and line items.", ["quote"], ["default"]],
  ["quote.delete", "Delete Quote", "Quotes", "Deletes a quote after explicit confirmation.", ["quote"], ["default"]],
  ["quote.add_line_item", "Add Quote Line Item", "Quotes", "Adds a line item to a quote.", ["quote"], ["default"]],
  ["quote.remove_line_item", "Remove Quote Line Item", "Quotes", "Removes matching quote line items.", ["quote"], ["default"]],
  ["quote.replace_line_items", "Replace Quote Line Items", "Quotes", "Replaces all quote line items.", ["quote"], ["default"]],
  ["quote.set_status", "Set Quote Status", "Quotes", "Sets quote lifecycle status.", ["quote"], ["default"]],
  ["quote.mark_sent", "Mark Quote Sent", "Quotes", "Marks a quote sent.", ["quote"], ["default"]],
  ["quote.mark_accepted", "Mark Quote Accepted", "Quotes", "Marks a quote accepted.", ["quote"], ["default"]],
  ["quote.mark_declined", "Mark Quote Declined", "Quotes", "Marks a quote declined.", ["quote"], ["default"]],
  ["quote.set_expiration", "Set Quote Expiration", "Quotes", "Sets quote expiration.", ["quote"], ["default"]],
  ["quote.convert_to_job", "Convert Quote to Job", "Quotes", "Creates a scheduled job from a quote.", ["quote"], ["default"]],
  ["quote.create_followup_task", "Create Quote Follow-Up Task", "Quotes", "Creates a quote follow-up task.", ["quote"], ["default"]],
  ["quote.create_invoice", "Create Invoice from Quote", "Invoices", "Creates a lightweight invoice record from a quote.", ["quote"], ["default"]],
  ["invoice.create", "Create Invoice", "Invoices", "Creates a durable invoice record.", ["contact"], ["default"]],
  ["invoice.issue", "Issue Invoice", "Invoices", "Marks an invoice issued.", ["invoice"], ["default"]],
  ["invoice.set_due_date", "Set Invoice Due Date", "Invoices", "Sets an invoice due date.", ["invoice"], ["default"]],
  ["invoice.void", "Void Invoice", "Invoices", "Voids an invoice.", ["invoice"], ["default"]],
  ["invoice.create_payment_request", "Create Invoice Payment Request", "Invoices", "Creates a Stripe payment request for an invoice.", ["invoice"], ["default"]],
  ["invoice.generate_pdf", "Generate Invoice PDF", "Invoices", "Deferred because PDF generation is currently iOS-side.", ["invoice"], ["default"]],
  ["invoice.send_payment_link", "Send Invoice Payment Link", "Invoices", "Creates a payment request and sends it by SMS.", ["invoice"], ["default"]],
  ["invoice.create_followup_task", "Create Invoice Follow-Up Task", "Invoices", "Creates an invoice follow-up task.", ["invoice"], ["default"]],
  ["payment.create_request", "Create Payment Request", "Payments", "Creates a Stripe PaymentIntent using the connected account.", ["contact"], ["default"]],
  ["payment.create_payment_link", "Create Payment Link", "Payments", "Creates a payment request/link reference where supported.", ["contact"], ["default"]],
  ["payment.create_followup_task", "Create Payment Follow-Up Task", "Payments", "Creates a payment follow-up task.", ["payment"], ["default"]],
  ["payment.send_payment_sms", "Send Payment SMS", "Payments", "Sends a payment follow-up SMS through the shared SMS safety path.", ["payment", "contact"], ["default"]],
  ["payment.send_payment_push", "Send Payment Push", "Payments", "Sends a payment-related push notification.", ["payment"], ["default"]],
  ["payment.record_manual_payment", "Record Manual Payment", "Payments", "Creates a manual paid payment record.", ["contact"], ["default"]],
  ["service_plan.create", "Create Service Plan", "Service Plans", "Creates a service plan.", ["contact"], ["default"]],
  ["service_plan.update", "Update Service Plan", "Service Plans", "Updates service-plan fields.", ["service_plan"], ["default"]],
  ["service_plan.activate", "Activate Service Plan", "Service Plans", "Marks a plan active locally.", ["service_plan"], ["default"]],
  ["service_plan.pause", "Pause Service Plan", "Service Plans", "Pauses local service scheduling.", ["service_plan"], ["default"]],
  ["service_plan.resume", "Resume Service Plan", "Service Plans", "Resumes local service scheduling.", ["service_plan"], ["default"]],
  ["service_plan.cancel", "Cancel Service Plan", "Service Plans", "Cancels a plan using existing local/Stripe semantics.", ["service_plan"], ["default"]],
  ["service_plan.mark_serviced", "Mark Service Plan Serviced", "Service Plans", "Marks service completed and rolls next service date.", ["service_plan"], ["default"]],
  ["service_plan.set_price", "Set Service Plan Price", "Service Plans", "Sets service-plan price.", ["service_plan"], ["default"]],
  ["service_plan.set_service_interval", "Set Service Interval", "Service Plans", "Sets the service interval.", ["service_plan"], ["default"]],
  ["service_plan.set_billing_interval", "Set Billing Interval", "Service Plans", "Sets the billing interval.", ["service_plan"], ["default"]],
  ["service_plan.set_next_service_date", "Set Next Service Date", "Service Plans", "Sets the next service date.", ["service_plan"], ["default"]],
  ["service_plan.create_next_job", "Create Next Service Job", "Service Plans", "Creates a job for the next service.", ["service_plan"], ["default"]],
  ["service_plan.create_service_task", "Create Service Task", "Service Plans", "Creates a service scheduling task.", ["service_plan"], ["default"]],
  ["service_plan.send_scheduling_sms", "Send Service Scheduling SMS", "Service Plans", "Sends scheduling SMS through the shared SMS safety path.", ["service_plan"], ["default"]],
  ["service_plan.create_payment_followup", "Create Service Payment Follow-Up", "Service Plans", "Creates a payment follow-up task.", ["service_plan"], ["default"]],
  ["map.create_pin", "Create Map Pin", "Map & Canvassing", "Creates a company-scoped field map pin.", ["contact", "map_pin"], ["default"]],
  ["map.update_pin", "Update Map Pin", "Map & Canvassing", "Updates safe map pin fields.", ["map_pin"], ["default"]],
  ["map.delete_pin", "Delete Map Pin", "Map & Canvassing", "Deletes a map pin after explicit confirmation.", ["map_pin"], ["default"]],
  ["map.set_status", "Set Map Status", "Map & Canvassing", "Sets a pin status using WolfCRM map states.", ["map_pin"], ["default"]],
  ["map.add_to_list", "Add Pin to List", "Map & Canvassing", "Adds a pin to a durable automation map list.", ["map_pin"], ["default"]],
  ["map.remove_from_list", "Remove Pin from List", "Map & Canvassing", "Removes a pin from its durable automation map list.", ["map_pin"], ["default"]],
  ["map.move_to_list", "Move Pin to List", "Map & Canvassing", "Moves a pin to a durable automation map list.", ["map_pin"], ["default"]],
  ["map.link_contact", "Link Pin to Contact", "Map & Canvassing", "Links a pin to a company contact.", ["map_pin", "contact"], ["default"]],
  ["map.unlink_contact", "Unlink Pin Contact", "Map & Canvassing", "Removes the contact link from a pin.", ["map_pin"], ["default"]],
  ["map.create_contact", "Create Contact from Pin", "Map & Canvassing", "Creates a contact from a pin and links it.", ["map_pin"], ["default"]],
  ["map.add_note", "Add Pin Note", "Map & Canvassing", "Adds a durable map activity note.", ["map_pin"], ["default"]],
  ["map.mark_visited", "Mark Pin Visited", "Map & Canvassing", "Records a field visit for a pin.", ["map_pin"], ["default"]],
  ["map.record_knock", "Record Door Knock", "Map & Canvassing", "Records a door knock/outcome for a pin.", ["map_pin"], ["default"]],
  ["map.schedule_followup", "Schedule Pin Follow-Up", "Map & Canvassing", "Schedules a pin follow-up event.", ["map_pin"], ["default"]],
  ["map.add_to_route", "Add Pin to Route", "Map & Canvassing", "Adds a pin as a route stop.", ["map_pin", "route"], ["default"]],
  ["route.create", "Create Route", "Routes", "Creates a durable field route.", ["generic"], ["default"]],
  ["route.delete", "Delete Route", "Routes", "Deletes a route after confirmation.", ["route"], ["default"]],
  ["route.add_stop", "Add Route Stop", "Routes", "Adds a stop to a route.", ["route"], ["default"]],
  ["route.remove_stop", "Remove Route Stop", "Routes", "Removes a route stop.", ["route_stop"], ["default"]],
  ["route.add_contact", "Add Contact to Route", "Routes", "Adds a contact location to a route.", ["route", "contact"], ["default"]],
  ["route.add_pin", "Add Pin to Route", "Routes", "Adds a map pin to a route.", ["route", "map_pin"], ["default"]],
  ["route.assign_user", "Assign Route Rep", "Routes", "Assigns a route to a company user.", ["route", "employee"], ["default"]],
  ["route.set_date", "Set Route Date", "Routes", "Sets the scheduled route date.", ["route"], ["default"]],
  ["route.optimize", "Optimize Stop Order", "Routes", "Deterministically reorders stops by coordinate distance.", ["route"], ["default"]],
  ["route.mark_started", "Mark Route Started", "Routes", "Marks a route started.", ["route"], ["default"]],
  ["route.mark_completed", "Mark Route Completed", "Routes", "Marks a route completed.", ["route"], ["default"]],
  ["route.complete_stop", "Complete Route Stop", "Routes", "Marks a route stop completed.", ["route_stop"], ["default"]],
  ["route.skip_stop", "Skip Route Stop", "Routes", "Marks a route stop skipped.", ["route_stop"], ["default"]],
  ["employee.update_role", "Update Employee Role", "Employees & Team", "Updates an employee role with safeguards.", ["employee"], ["default"]],
  ["employee.deactivate", "Deactivate Employee", "Employees & Team", "Soft-deactivates an employee with confirmation.", ["employee"], ["default"]],
  ["employee.reactivate", "Reactivate Employee", "Employees & Team", "Restores a deactivated employee.", ["employee"], ["default"]],
  ["employee.send_push", "Send Employee Push", "Employees & Team", "Sends a push notification to an employee.", ["employee"], ["default"]],
  ["employee.send_internal_message", "Send Employee Internal Message", "Employees & Team", "Sends an internal DM to an employee.", ["employee"], ["default"]],
  ["employee.create_task", "Create Employee Task", "Employees & Team", "Creates a task assigned to an employee.", ["employee"], ["default"]],
  ["time_clock.create_review_task", "Create Time Review Task", "Time Clock", "Creates a task to review a time entry.", ["time_entry"], ["default"]],
  ["time_clock.send_employee_reminder", "Send Time Reminder", "Time Clock", "Sends an internal reminder to an employee.", ["time_entry", "employee"], ["default"]],
  ["time_clock.notify_manager", "Notify Manager", "Time Clock", "Sends an operational notification to managers.", ["time_entry"], ["default"]],
  ["time_clock.flag_for_review", "Flag Time Entry", "Time Clock", "Flags a time entry for employer review.", ["time_entry"], ["default"]],
  ["time_clock.clear_review_flag", "Clear Time Review Flag", "Time Clock", "Clears a time entry review flag.", ["time_entry"], ["default"]],
  ["measurement.create_record", "Create Measurement Record", "Measurements", "Creates a saved measurement record.", ["generic"], ["default"]],
  ["measurement.update_label", "Update Measurement Label", "Measurements", "Updates a measurement name.", ["measurement"], ["default"]],
  ["measurement.link_contact", "Link Measurement to Contact", "Measurements", "Links a measurement to a contact.", ["measurement", "contact"], ["default"]],
  ["measurement.link_pin", "Link Measurement to Pin", "Measurements", "Deferred until measurements persist pin links.", ["measurement", "map_pin"], ["default"]],
  ["job.create", "Create Job", "Schedule", "Creates a scheduled job.", ["contact"], ["default"]],
  ["job.update", "Update Job", "Schedule & Jobs", "Updates whitelisted job fields.", ["job"], ["default"]],
  ["job.reschedule", "Reschedule Job", "Schedule & Jobs", "Changes a job start/end time.", ["job"], ["default"]],
  ["job.cancel", "Cancel Job", "Schedule & Jobs", "Reserved for future cancellation status; current app distinguishes delete from complete.", ["job"], ["default"]],
  ["job.delete", "Delete Job", "Schedule & Jobs", "Deletes a job after explicit confirmation.", ["job"], ["default"]],
  ["job.restore", "Restore Job", "Schedule & Jobs", "Deferred because deleted job recovery is currently local-only.", ["job"], ["default"]],
  ["job.mark_completed", "Mark Job Completed", "Schedule & Jobs", "Marks a job finished using the current schedule state.", ["job"], ["default"]],
  ["job.reopen", "Reopen Job", "Schedule & Jobs", "Clears the finished state on a job.", ["job"], ["default"]],
  ["job.set_start", "Set Job Start", "Schedule & Jobs", "Sets the job start time.", ["job"], ["default"]],
  ["job.set_end", "Set Job End", "Schedule & Jobs", "Sets the job end time.", ["job"], ["default"]],
  ["job.set_price", "Set Job Price", "Schedule & Jobs", "Sets the job price.", ["job"], ["default"]],
  ["job.set_material_cost", "Set Material Cost", "Schedule & Jobs", "Sets material cost.", ["job"], ["default"]],
  ["job.set_color", "Set Job Color", "Schedule & Jobs", "Sets the job color.", ["job"], ["default"]],
  ["job.set_contact", "Set Job Contact", "Schedule & Jobs", "Links a job to a contact.", ["job"], ["default"]],
  ["job.add_service", "Add Job Service", "Schedule & Jobs", "Adds a service item to a job.", ["job"], ["default"]],
  ["job.remove_service", "Remove Job Service", "Schedule & Jobs", "Removes matching service items from a job.", ["job"], ["default"]],
  ["job.assign_worker", "Assign Worker", "Schedule & Jobs", "Adds a worker to a job.", ["job"], ["default"]],
  ["job.remove_worker", "Remove Worker", "Schedule & Jobs", "Removes a worker from a job.", ["job"], ["default"]],
  ["job.replace_workers", "Replace Workers", "Schedule & Jobs", "Replaces the job worker list.", ["job"], ["default"]],
  ["job.assign_salesperson", "Assign Salesperson", "Schedule & Jobs", "Adds a salesperson to a job.", ["job"], ["default"]],
  ["job.remove_salesperson", "Remove Salesperson", "Schedule & Jobs", "Removes a salesperson from a job.", ["job"], ["default"]],
  ["job.replace_salespeople", "Replace Salespeople", "Schedule & Jobs", "Replaces the job salesperson list.", ["job"], ["default"]],
  ["job.add_note", "Add Job Note", "Schedule & Jobs", "Appends text to the job notes field.", ["job"], ["default"]],
  ["job.create_followup", "Create Follow-Up Job", "Schedule & Jobs", "Creates a future job based on the current job.", ["job"], ["default"]],
  ["schedule.find_available_slots", "Find Available Slots", "Schedule & Jobs", "Deterministically finds open schedule windows.", ["generic"], ["default"]],
  ["task.update", "Update Task", "Tasks", "Updates whitelisted task fields.", ["task"], ["default"]],
  ["task.complete", "Complete Task", "Tasks", "Marks a task completed.", ["task"], ["default"]],
  ["task.reopen", "Reopen Task", "Tasks", "Marks a task incomplete.", ["task"], ["default"]],
  ["task.delete", "Delete Task", "Tasks", "Deletes a task.", ["task"], ["default"]],
  ["task.reschedule", "Reschedule Task", "Tasks", "Changes a task due date.", ["task"], ["default"]],
  ["task.assign", "Assign Task", "Tasks", "Moves a personal task to another company user.", ["task"], ["default"]],
  ["task.unassign", "Unassign Task", "Tasks", "Moves a task back to the company owner.", ["task"], ["default"]],
  ["task.add_subtask", "Add Subtask", "Tasks", "Adds a subtask.", ["task"], ["default"]],
  ["task.complete_subtask", "Complete Subtask", "Tasks", "Marks a subtask completed.", ["task"], ["default"]],
  ["task.delete_subtask", "Delete Subtask", "Tasks", "Deletes a subtask.", ["task"], ["default"]],
  ["routine.create", "Create Routine", "Routines", "Creates a recurring routine.", ["generic"], ["default"]],
  ["routine.update", "Update Routine", "Routines", "Updates a routine.", ["routine"], ["default"]],
  ["routine.mark_completed", "Mark Routine Completed", "Routines", "Completes an occurrence.", ["routine"], ["default"]],
  ["routine.end", "End Routine", "Routines", "Disables a routine.", ["routine"], ["default"]],
  ["customer_reminder.create", "Create Customer Reminder", "Customer Reminders", "Creates a customer reminder.", ["contact"], ["default"]],
  ["customer_reminder.complete", "Complete Customer Reminder", "Customer Reminders", "Marks a customer reminder complete.", ["customer_reminder"], ["default"]],
  ["customer_reminder.reschedule", "Reschedule Customer Reminder", "Customer Reminders", "Changes reminder due date.", ["customer_reminder"], ["default"]],
  ["customer_reminder.delete", "Delete Customer Reminder", "Customer Reminders", "Deletes a customer reminder.", ["customer_reminder"], ["default"]],
  ["customer_reminder.reopen", "Reopen Customer Reminder", "Customer Reminders", "Marks a customer reminder incomplete.", ["customer_reminder"], ["default"]],
  ["contacts.search", "Search Contacts", "Collections", "Finds company contacts using bounded filters.", ["generic"], ["default"]],
  ["jobs.search", "Search Jobs", "Collections", "Finds jobs using bounded company-scoped filters.", ["generic"], ["default"]],
  ["tasks.search", "Search Tasks", "Collections", "Finds tasks using bounded company-scoped filters.", ["generic"], ["default"]],
  ["map.search_pins", "Search Map Pins", "Collections", "Finds map pins using bounded company-scoped filters.", ["generic"], ["default"]],
  ["route.get_stops", "Get Route Stops", "Collections", "Returns route stops for the current or selected route.", ["route"], ["default"]],
  ["quotes.search", "Search Quotes", "Collections", "Finds quote records using bounded filters.", ["generic"], ["default"]],
  ["payments.search", "Search Payments", "Collections", "Finds payment records using bounded filters.", ["generic"], ["default"]],
  ["service_plans.search", "Search Service Plans", "Collections", "Finds service plans using bounded filters.", ["generic"], ["default"]],
  ["employees.search", "Search Employees", "Collections", "Finds active or inactive company users.", ["generic"], ["default"]],
  ["collection.filter", "Filter Collection", "Collections", "Filters a collection with the canonical condition engine.", ["generic"], ["default"]],
  ["collection.map", "Map Collection", "Collections", "Builds a deterministic mapped collection from templates.", ["generic"], ["default"]],
  ["collection.sort", "Sort Collection", "Collections", "Sorts a collection by a field.", ["generic"], ["default"]],
  ["collection.limit", "Limit Collection", "Collections", "Limits a collection to a bounded number of items.", ["generic"], ["default"]],
  ["collection.first", "First Item", "Collections", "Returns the first item in a collection.", ["generic"], ["default"]],
  ["collection.last", "Last Item", "Collections", "Returns the last item in a collection.", ["generic"], ["default"]],
  ["collection.count", "Count Items", "Collections", "Counts collection items.", ["generic"], ["default"]],
  ["collection.unique", "Unique Items", "Collections", "Deduplicates collection items.", ["generic"], ["default"]],
  ["collection.concat", "Concat Collections", "Collections", "Combines bounded collections.", ["generic"], ["default"]],
  ["collection.flatten", "Flatten Collection", "Collections", "Flattens one array level.", ["generic"], ["default"]],
  ["collection.contains", "Collection Contains", "Collections", "Checks whether a collection contains a value.", ["generic"], ["default"]],
  ["variable.increment", "Increment Variable", "Variables", "Atomically increments a numeric run variable.", ["generic"], ["default"]],
  ["variable.append", "Append Variable", "Variables", "Atomically appends to a run-scoped list variable.", ["generic"], ["default"]],
  ["object.get", "Get Object Field", "Data", "Reads a safe path from an object.", ["generic"], ["default"]],
  ["object.build", "Build Object", "Data", "Builds a JSON object from template mappings.", ["generic"], ["default"]],
  ["coalesce", "First Non-Empty", "Data", "Returns the first non-empty configured value.", ["generic"], ["default"]],
  ["math", "Math", "Data", "Runs a deterministic numeric operation.", ["generic"], ["default"]],
  ["text", "Text Transform", "Data", "Runs deterministic text operations.", ["generic"], ["default"]],
  ["date", "Date Transform", "Data", "Runs deterministic date operations using company timezone context.", ["generic"], ["default"]],
  ["webhook.send", "Send Webhook", "Webhooks", "Sends a bounded HTTP request to an external URL.", ["generic"], ["default"]],
  ["automation.start", "Start Automation", "Automations", "Starts another published automation.", ["generic"], ["default"]]
].map(([key, displayName, category, description, subjectTypes, outputs]) => ({
  key,
  display_name: displayName,
  category,
  description,
  supported_subject_types: subjectTypes,
  outputs,
  icon: actionIcon(key),
  visibility: actionVisibility(key),
  ...deprecationFor(key),
  config_fields: actionConfigFields(key)
}));

const actionExecutors = {
  "contact.create": executeContactCreate,
  "contact.delete": executeContactDelete,
  "contact.restore": executeDeferredAction,
  "contact.add_tag": executeContactAddTag,
  "contact.remove_tag": executeContactRemoveTag,
  "contact.replace_tags": executeContactReplaceTags,
  "contact.clear_tags": executeContactClearTags,
  "contact.update_fields": executeContactUpdateFields,
  "contact.assign_user": executeDeferredAction,
  "contact.unassign_user": executeDeferredAction,
  "contact.set_source": executeContactSetSource,
  "contact.set_value": executeContactSetValue,
  "contact.set_job_type": executeContactSetJobType,
  "contact.set_custom_field": executeContactSetCustomField,
  "contact.set_location": executeContactSetLocation,
  "contact.add_note": executeContactAddNote,
  "contact.add_activity": executeContactAddActivity,
  "contact.add_to_map": executeContactAddToMap,
  "pipeline.create_opportunity": executePipelineCreateOpportunity,
  "pipeline.move_stage": executePipelineMoveStage,
  "pipeline.remove_opportunity": executePipelineRemoveOpportunity,
  "pipeline.mark_won": executePipelineMarkWon,
  "pipeline.mark_lost": executePipelineMarkLost,
  "pipeline.reopen": executePipelineReopen,
  "pipeline.set_value": executePipelineSetValue,
  "pipeline.assign_salesperson": executeDeferredAction,
  "pipeline.remove_salesperson": executeDeferredAction,
  "pipeline.create_reminder": executePipelineCreateReminder,
  "pipeline.complete_reminder": executePipelineCompleteReminder,
  "pipeline.archive_reminder": executePipelineArchiveReminder,
  "task.create": executeTaskCreate,
  "notification.send_push": executePushNotification,
  "sms.send": executeSmsSend,
  "sms.send_mms": executeMmsSend,
  "sms.mark_conversation_read": executeSmsConversationRead,
  "sms.mark_conversation_unread": executeSmsConversationUnread,
  "sms.delete_local_message": executeSmsDeleteLocalMessage,
  "sms.delete_local_conversation": executeSmsDeleteLocalConversation,
  "phone.create_contact_from_number": executeCreateContactFromNumber,
  "internal.send_message": executeInternalMessage,
  "internal.send_dm": executeInternalDm,
  "internal.send_group_message": executeInternalGroupMessage,
  "internal.send_channel_message": executeInternalChannelMessage,
  "internal.create_group": executeInternalCreateGroup,
  "internal.create_channel": executeInternalCreateChannel,
  "internal.mark_conversation_read": executeInternalMarkConversationRead,
  "call.set_disposition": executeCallSetDisposition,
  "call.create_callback_task": executeCallCreateCallbackTask,
  "call.send_followup_sms": executeCallFollowupSms,
  "call.add_contact_note": executeCallAddContactNote,
  "voicemail.mark_read": executeVoicemailMarkRead,
  "voicemail.mark_unread": executeVoicemailMarkUnread,
  "voicemail.delete": executeVoicemailDelete,
  "voicemail.create_callback_task": executeVoicemailCreateCallbackTask,
  "voicemail.send_followup_sms": executeVoicemailFollowupSms,
  "quote.create": executeQuoteCreate,
  "quote.update": executeQuoteUpdate,
  "quote.delete": executeQuoteDelete,
  "quote.add_line_item": executeQuoteAddLineItem,
  "quote.remove_line_item": executeQuoteRemoveLineItem,
  "quote.replace_line_items": executeQuoteReplaceLineItems,
  "quote.set_status": executeQuoteSetStatus,
  "quote.mark_sent": executeQuoteMarkSent,
  "quote.mark_accepted": executeQuoteMarkAccepted,
  "quote.mark_declined": executeQuoteMarkDeclined,
  "quote.set_expiration": executeQuoteSetExpiration,
  "quote.convert_to_job": executeQuoteConvertToJob,
  "quote.create_followup_task": executeQuoteFollowupTask,
  "quote.create_invoice": executeQuoteCreateInvoice,
  "invoice.create": executeInvoiceCreate,
  "invoice.issue": executeInvoiceIssue,
  "invoice.set_due_date": executeInvoiceSetDueDate,
  "invoice.void": executeInvoiceVoid,
  "invoice.create_payment_request": executeInvoiceCreatePaymentRequest,
  "invoice.generate_pdf": executeDeferredAction,
  "invoice.send_payment_link": executeInvoiceSendPaymentLink,
  "invoice.create_followup_task": executeInvoiceFollowupTask,
  "payment.create_request": executePaymentCreateRequest,
  "payment.create_payment_link": executePaymentCreateRequest,
  "payment.create_followup_task": executePaymentFollowupTask,
  "payment.send_payment_sms": executePaymentSendSms,
  "payment.send_payment_push": executePaymentSendPush,
  "payment.record_manual_payment": executePaymentRecordManual,
  "service_plan.create": executeServicePlanCreate,
  "service_plan.update": executeServicePlanUpdate,
  "service_plan.activate": executeServicePlanActivate,
  "service_plan.pause": executeServicePlanPause,
  "service_plan.resume": executeServicePlanResume,
  "service_plan.cancel": executeServicePlanCancel,
  "service_plan.mark_serviced": executeServicePlanMarkServiced,
  "service_plan.set_price": executeServicePlanSetPrice,
  "service_plan.set_service_interval": executeServicePlanSetServiceInterval,
  "service_plan.set_billing_interval": executeServicePlanSetBillingInterval,
  "service_plan.set_next_service_date": executeServicePlanSetNextServiceDate,
  "service_plan.create_next_job": executeServicePlanCreateNextJob,
  "service_plan.create_service_task": executeServicePlanCreateTask,
  "service_plan.send_scheduling_sms": executeServicePlanSendSchedulingSms,
  "service_plan.create_payment_followup": executeServicePlanPaymentFollowup,
  "map.create_pin": executeMapCreatePin,
  "map.update_pin": executeMapUpdatePin,
  "map.delete_pin": executeMapDeletePin,
  "map.set_status": executeMapSetStatus,
  "map.add_to_list": executeMapAddToList,
  "map.remove_from_list": executeMapRemoveFromList,
  "map.move_to_list": executeMapMoveToList,
  "map.link_contact": executeMapLinkContact,
  "map.unlink_contact": executeMapUnlinkContact,
  "map.create_contact": executeMapCreateContact,
  "map.add_note": executeMapAddNote,
  "map.mark_visited": executeMapMarkVisited,
  "map.record_knock": executeMapRecordKnock,
  "map.schedule_followup": executeMapScheduleFollowup,
  "map.add_to_route": executeMapAddToRoute,
  "route.create": executeRouteCreate,
  "route.delete": executeRouteDelete,
  "route.add_stop": executeRouteAddStop,
  "route.remove_stop": executeRouteRemoveStop,
  "route.add_contact": executeRouteAddContact,
  "route.add_pin": executeRouteAddPin,
  "route.add_job": executeRouteAddJob,
  "route.assign_user": executeRouteAssignUser,
  "route.set_date": executeRouteSetDate,
  "route.optimize": executeRouteOptimize,
  "route.mark_started": executeRouteMarkStarted,
  "route.mark_completed": executeRouteMarkCompleted,
  "route.complete_stop": executeRouteCompleteStop,
  "route.skip_stop": executeRouteSkipStop,
  "employee.update_role": executeEmployeeUpdateRole,
  "employee.deactivate": executeEmployeeDeactivate,
  "employee.reactivate": executeEmployeeReactivate,
  "employee.send_push": executeEmployeeSendPush,
  "employee.send_internal_message": executeEmployeeSendInternalMessage,
  "employee.create_task": executeEmployeeCreateTask,
  "time_clock.create_review_task": executeTimeClockCreateReviewTask,
  "time_clock.send_employee_reminder": executeTimeClockSendEmployeeReminder,
  "time_clock.notify_manager": executeTimeClockNotifyManager,
  "time_clock.flag_for_review": executeTimeClockFlagForReview,
  "time_clock.clear_review_flag": executeTimeClockClearReviewFlag,
  "measurement.create_record": executeMeasurementCreateRecord,
  "measurement.update_label": executeMeasurementUpdateLabel,
  "measurement.link_contact": executeMeasurementLinkContact,
  "measurement.link_pin": executeDeferredAction,
  "job.create": executeJobCreate,
  "job.update": executeJobUpdate,
  "job.reschedule": executeJobReschedule,
  "job.cancel": executeDeferredAction,
  "job.delete": executeJobDelete,
  "job.restore": executeDeferredAction,
  "job.mark_completed": executeJobMarkCompleted,
  "job.reopen": executeJobReopen,
  "job.set_start": executeJobSetStart,
  "job.set_end": executeJobSetEnd,
  "job.set_price": executeJobSetPrice,
  "job.set_material_cost": executeJobSetMaterialCost,
  "job.set_color": executeJobSetColor,
  "job.set_contact": executeJobSetContact,
  "job.add_service": executeJobAddService,
  "job.remove_service": executeJobRemoveService,
  "job.assign_worker": executeJobAssignWorker,
  "job.remove_worker": executeJobRemoveWorker,
  "job.replace_workers": executeJobReplaceWorkers,
  "job.assign_salesperson": executeJobAssignSalesperson,
  "job.remove_salesperson": executeJobRemoveSalesperson,
  "job.replace_salespeople": executeJobReplaceSalespeople,
  "job.add_note": executeJobAddNote,
  "job.create_followup": executeJobCreateFollowup,
  "schedule.find_available_slots": executeFindAvailableSlots,
  "task.update": executeTaskUpdate,
  "task.complete": executeTaskComplete,
  "task.reopen": executeTaskReopen,
  "task.delete": executeTaskDelete,
  "task.reschedule": executeTaskReschedule,
  "task.assign": executeTaskAssign,
  "task.unassign": executeTaskUnassign,
  "task.add_subtask": executeTaskAddSubtask,
  "task.complete_subtask": executeTaskCompleteSubtask,
  "task.delete_subtask": executeTaskDeleteSubtask,
  "routine.create": executeRoutineCreate,
  "routine.update": executeRoutineUpdate,
  "routine.mark_completed": executeRoutineMarkCompleted,
  "routine.end": executeRoutineEnd,
  "customer_reminder.create": executeCustomerReminderCreate,
  "customer_reminder.complete": executeCustomerReminderComplete,
  "customer_reminder.reschedule": executeCustomerReminderReschedule,
  "customer_reminder.delete": executeCustomerReminderDelete,
  "customer_reminder.reopen": executeCustomerReminderReopen,
  "contacts.search": executeContactsSearch,
  "jobs.search": executeJobsSearch,
  "tasks.search": executeTasksSearch,
  "map.search_pins": executeMapSearchPins,
  "route.get_stops": executeRouteGetStops,
  "quotes.search": executeQuotesSearch,
  "payments.search": executePaymentsSearch,
  "service_plans.search": executeServicePlansSearch,
  "employees.search": executeEmployeesSearch,
  "collection.filter": executeCollectionFilter,
  "collection.map": executeCollectionMap,
  "collection.sort": executeCollectionSort,
  "collection.limit": executeCollectionLimit,
  "collection.first": executeCollectionFirst,
  "collection.last": executeCollectionLast,
  "collection.count": executeCollectionCount,
  "collection.unique": executeCollectionUnique,
  "collection.concat": executeCollectionConcat,
  "collection.flatten": executeCollectionFlatten,
  "collection.contains": executeCollectionContains,
  "variable.increment": executeVariableIncrement,
  "variable.append": executeVariableAppend,
  "object.get": executeObjectGet,
  "object.build": executeObjectBuild,
  "coalesce": executeCoalesce,
  "math": executeMath,
  "text": executeText,
  "date": executeDateTransform,
  "webhook.send": executeWebhookSend,
  "automation.start": executeAutomationStart
};

function actionConfigFields(key) {
  const commonText = (name, label) => ({ key: name, label, type: "text" });
  switch (key) {
    case "contact.create":
      return ["name", "phone", "email", "address", "job_type", "source", "u1", "u2", "u3", "u4", "u5"].map((field) => commonText(field, field))
        .concat([{ key: "value_cents", label: "Value", type: "money" }, { key: "tags", label: "Tags", type: "tag_list" }, { key: "lat", label: "Latitude", type: "number" }, { key: "lng", label: "Longitude", type: "number" }]);
    case "contact.add_tag":
    case "contact.remove_tag":
    case "contact.replace_tags":
      return [{ key: "tags", label: "Tags", type: "tag_list" }];
    case "contact.clear_tags":
      return [];
    case "contact.update_fields":
      return ["name", "phone", "email", "address", "job_type", "source", "u1", "u2", "u3", "u4", "u5"].map((field) => commonText(field, field))
        .concat([{ key: "value_cents", label: "Value", type: "money" }, { key: "lat", label: "Latitude", type: "number" }, { key: "lng", label: "Longitude", type: "number" }]);
    case "contact.set_source":
      return [commonText("source", "Source")];
    case "contact.set_value":
    case "pipeline.set_value":
      return [{ key: "value_cents", label: "Value", type: "money" }];
    case "contact.set_job_type":
      return [commonText("job_type", "Job Type")];
    case "contact.set_custom_field":
      return [{ key: "field", label: "Custom Field", type: "select", options: ["u1", "u2", "u3", "u4", "u5"] }, commonText("value", "Value")];
    case "contact.set_location":
      return [{ key: "lat", label: "Latitude", type: "number" }, { key: "lng", label: "Longitude", type: "number" }];
    case "contact.delete":
      return [{ key: "confirm_delete", label: "Confirm Delete", type: "boolean" }];
    case "contact.add_note":
    case "contact.add_activity":
      return [commonText("body", "Note"), { key: "activity_type", label: "Activity Type", type: "select", options: ["note", "call", "message", "email"] }];
    case "contact.add_to_map":
      return [{ key: "status", label: "Status", type: "select", options: ["lead", "won", "reloop", "later", "lost"] }, commonText("notes", "Notes")];
    case "pipeline.create_opportunity":
      return [{ key: "stage_id", label: "Stage ID", type: "stage" }, { key: "if_exists", label: "If Exists", type: "select", options: ["reuse", "fail", "move"] }];
    case "pipeline.move_stage":
    case "pipeline.reopen":
      return [{ key: "stage_id", label: "Stage ID", type: "stage" }, { key: "if_missing", label: "If Missing", type: "select", options: ["fail", "create"] }];
    case "pipeline.mark_lost":
      return [commonText("reason", "Reason")];
    case "pipeline.create_reminder":
      return [commonText("note", "Message"), { key: "remind_at", label: "Remind At", type: "datetime" }];
    case "pipeline.complete_reminder":
    case "pipeline.archive_reminder":
      return [commonText("reminder_id", "Reminder ID")];
    case "task.create":
      return [commonText("title", "Title"), commonText("notes", "Notes"), { key: "due_date", label: "Due Date", type: "datetime" }, { key: "assigned_user_id", label: "Assignee", type: "user" }];
    case "notification.send_push":
      return [commonText("title", "Title"), commonText("body", "Body"), { key: "user_ids", label: "Recipients", type: "user_list" }];
    case "sms.send":
    case "sms.send_mms":
    case "call.send_followup_sms":
    case "voicemail.send_followup_sms":
      return [commonText("body", "Message"), commonText("phone", "Phone/Template"), commonText("contact_id", "Contact ID"), commonText("conversation_id", "Conversation ID"), { key: "business_hours_policy", label: "Business Hours Policy", type: "select", options: ["send_immediately", "defer_until_business_hours", "skip_if_outside_business_hours"] }, { key: "media", label: "Media", type: "json" }];
    case "sms.mark_conversation_read":
    case "sms.mark_conversation_unread":
    case "sms.delete_local_conversation":
      return [commonText("conversation_id", "Conversation ID")];
    case "sms.delete_local_message":
      return [commonText("message_id", "Message ID")];
    case "phone.create_contact_from_number":
      return [commonText("name", "Name"), commonText("phone", "Phone")];
    case "internal.send_message":
    case "internal.send_dm":
    case "internal.send_group_message":
    case "internal.send_channel_message":
      return [commonText("body", "Message"), commonText("conversation_id", "Conversation ID"), commonText("channel_id", "Channel ID"), commonText("recipient_user_id", "Recipient"), { key: "recipient_user_ids", label: "Recipients", type: "user_list" }];
    case "internal.create_group":
      return [commonText("title", "Title"), { key: "recipient_user_ids", label: "Members", type: "user_list" }];
    case "internal.create_channel":
      return [commonText("name", "Name"), commonText("description", "Description")];
    case "call.set_disposition":
      return [commonText("disposition", "Disposition")];
    case "call.create_callback_task":
    case "voicemail.create_callback_task":
      return [commonText("title", "Title"), commonText("notes", "Notes"), { key: "due_date", label: "Due Date", type: "datetime_expression" }, { key: "assigned_user_id", label: "Assignee", type: "user" }];
    case "call.add_contact_note":
      return [commonText("body", "Note")];
    case "job.create":
    case "job.update":
      return [commonText("title", "Title"), { key: "start_at", label: "Start", type: "datetime_expression" }, { key: "end_at", label: "End", type: "datetime_expression" }, commonText("notes", "Notes"), commonText("contact_id", "Contact ID"), { key: "price_cents", label: "Price", type: "money" }, { key: "material_cost_cents", label: "Material Cost", type: "money" }, commonText("color", "Color"), { key: "service_items", label: "Services", type: "json" }, { key: "worker_user_ids", label: "Workers", type: "user_list" }, { key: "sales_user_ids", label: "Salespeople", type: "user_list" }];
    case "job.reschedule":
      return [{ key: "start_at", label: "New Start", type: "datetime_expression" }, { key: "end_at", label: "New End", type: "datetime_expression" }, { key: "preserve_duration", label: "Preserve Duration", type: "boolean" }];
    case "job.delete":
      return [{ key: "confirm_delete", label: "Confirm Delete", type: "boolean" }];
    case "job.set_start":
      return [{ key: "start_at", label: "Start", type: "datetime_expression" }];
    case "job.set_end":
      return [{ key: "end_at", label: "End", type: "datetime_expression" }];
    case "job.set_price":
      return [{ key: "price_cents", label: "Price", type: "money" }];
    case "job.set_material_cost":
      return [{ key: "material_cost_cents", label: "Material Cost", type: "money" }];
    case "job.set_color":
      return [commonText("color", "Color")];
    case "job.set_contact":
      return [commonText("contact_id", "Contact ID")];
    case "job.add_service":
    case "job.remove_service":
      return [commonText("service", "Service"), { key: "price_cents", label: "Price", type: "money" }];
    case "job.assign_worker":
    case "job.remove_worker":
      return [commonText("user_id", "Worker")];
    case "job.replace_workers":
      return [{ key: "worker_user_ids", label: "Workers", type: "user_list" }];
    case "job.assign_salesperson":
    case "job.remove_salesperson":
      return [commonText("user_id", "Salesperson")];
    case "job.replace_salespeople":
      return [{ key: "sales_user_ids", label: "Salespeople", type: "user_list" }];
    case "job.add_note":
      return [commonText("notes", "Note")];
    case "job.create_followup":
      return [{ key: "amount", label: "Amount", type: "number" }, { key: "unit", label: "Unit", type: "select", options: ["days", "weeks", "months"] }, { key: "copy_services", label: "Copy Services", type: "boolean" }, { key: "copy_workers", label: "Copy Workers", type: "boolean" }, { key: "copy_salespeople", label: "Copy Salespeople", type: "boolean" }, { key: "copy_price", label: "Copy Price", type: "boolean" }];
    case "schedule.find_available_slots":
      return [{ key: "range_start", label: "Range Start", type: "datetime_expression" }, { key: "range_end", label: "Range End", type: "datetime_expression" }, { key: "duration_minutes", label: "Duration Minutes", type: "number" }, { key: "worker_user_ids", label: "Workers", type: "user_list" }];
    case "task.create":
    case "task.update":
      return [commonText("title", "Title"), commonText("notes", "Notes"), { key: "due_date", label: "Due Date", type: "datetime_expression" }, { key: "assigned_user_id", label: "Assignee", type: "user" }, { key: "subtasks", label: "Subtasks", type: "string_list" }];
    case "task.reschedule":
      return [{ key: "due_date", label: "Due Date", type: "datetime_expression" }];
    case "task.add_subtask":
      return [commonText("title", "Subtask")];
    case "task.complete_subtask":
    case "task.delete_subtask":
      return [commonText("title", "Subtask Title")];
    case "routine.create":
    case "routine.update":
      return [commonText("title", "Title"), { key: "time", label: "Time", type: "datetime_expression" }, { key: "weekdays", label: "Weekdays", type: "number_list" }];
    case "customer_reminder.create":
    case "customer_reminder.reschedule":
      return [commonText("title", "Title"), commonText("contact_id", "Contact ID"), commonText("contact_name", "Contact Name"), { key: "due_date", label: "Due Date", type: "datetime_expression" }];
    case "quote.create":
    case "quote.update":
      return [commonText("contact_id", "Contact ID"), commonText("title", "Title"), { key: "line_items", label: "Line Items", type: "line_items" }, commonText("notes", "Notes"), { key: "expires_at", label: "Expires At", type: "datetime_expression" }];
    case "quote.add_line_item":
      return [commonText("description", "Description"), { key: "qty", label: "Quantity", type: "number" }, { key: "price_cents", label: "Unit Price", type: "money" }];
    case "quote.remove_line_item":
      return [commonText("description", "Description")];
    case "quote.replace_line_items":
      return [{ key: "line_items", label: "Line Items", type: "line_items" }];
    case "quote.set_status":
      return [{ key: "status", label: "Status", type: "select", options: ["draft", "sent", "accepted", "declined", "expired", "converted"] }];
    case "quote.delete":
      return [{ key: "confirm_delete", label: "Confirm Delete", type: "boolean" }];
    case "quote.set_expiration":
      return [{ key: "expires_at", label: "Expires At", type: "datetime_expression" }];
    case "quote.convert_to_job":
      return [{ key: "start_at", label: "Job Start", type: "datetime_expression" }, { key: "end_at", label: "Job End", type: "datetime_expression" }, { key: "copy_total_to_price", label: "Copy Quote Total", type: "boolean" }, { key: "worker_user_ids", label: "Workers", type: "user_list" }, { key: "sales_user_ids", label: "Salespeople", type: "user_list" }];
    case "invoice.create":
      return [commonText("contact_id", "Contact ID"), commonText("quote_id", "Quote ID"), commonText("job_id", "Job ID"), { key: "line_items", label: "Line Items", type: "line_items" }, { key: "total_cents", label: "Total", type: "money" }, { key: "due_at", label: "Due At", type: "datetime_expression" }];
    case "invoice.issue":
    case "invoice.set_due_date":
      return [{ key: "due_at", label: "Due At", type: "datetime_expression" }];
    case "invoice.void":
      return [{ key: "confirm_void", label: "Confirm Void", type: "boolean" }];
    case "payment.create_request":
    case "payment.create_payment_link":
    case "invoice.create_payment_request":
      return [commonText("contact_id", "Contact ID"), { key: "amount_cents", label: "Amount", type: "money" }, commonText("description", "Description")];
    case "payment.record_manual_payment":
      return [commonText("contact_id", "Contact ID"), { key: "amount_cents", label: "Amount", type: "money" }, commonText("description", "Description")];
    case "service_plan.create":
    case "service_plan.update":
      return [commonText("contact_id", "Contact ID"), commonText("plan_name", "Plan Name"), { key: "price_cents", label: "Price", type: "money" }, { key: "billing_interval", label: "Billing Interval", type: "select", options: ["day", "week", "month", "year"] }, { key: "billing_interval_count", label: "Billing Count", type: "number" }, { key: "service_interval", label: "Service Interval", type: "select", options: ["day", "week", "month", "year"] }, { key: "service_interval_count", label: "Service Count", type: "number" }, { key: "first_service_date", label: "First Service Date", type: "date" }, { key: "next_service_date", label: "Next Service Date", type: "date" }];
    case "service_plan.cancel":
      return [{ key: "confirm_cancel", label: "Confirm Cancel", type: "boolean" }];
    case "service_plan.set_price":
      return [{ key: "price_cents", label: "Price", type: "money" }];
    case "service_plan.set_next_service_date":
      return [{ key: "next_service_date", label: "Next Service Date", type: "date" }];
    case "service_plan.set_service_interval":
      return [{ key: "service_interval", label: "Service Interval", type: "select", options: ["day", "week", "month", "year"] }, { key: "service_interval_count", label: "Count", type: "number" }];
    case "service_plan.set_billing_interval":
      return [{ key: "billing_interval", label: "Billing Interval", type: "select", options: ["day", "week", "month", "year"] }, { key: "billing_interval_count", label: "Count", type: "number" }];
    case "service_plan.create_next_job":
      return [{ key: "start_at", label: "Start", type: "datetime_expression" }, { key: "duration_minutes", label: "Duration", type: "number" }, { key: "worker_user_ids", label: "Workers", type: "user_list" }];
    case "service_plan.create_service_task":
    case "service_plan.create_payment_followup":
      return [commonText("title", "Title"), { key: "due_date", label: "Due Date", type: "datetime_expression" }];
    case "service_plan.send_scheduling_sms":
    case "payment.send_payment_sms":
      return [commonText("body", "Message"), { key: "business_hours_policy", label: "Business Hours", type: "select", options: ["send_immediately", "defer_until_business_hours", "skip_if_outside_business_hours"] }];
    case "map.create_pin":
    case "map.update_pin":
      return [commonText("pin_id", "Pin ID"), commonText("name", "Name"), commonText("address", "Address"), commonText("notes", "Notes"), { key: "latitude", label: "Latitude", type: "number" }, { key: "longitude", label: "Longitude", type: "number" }, { key: "status", label: "Status", type: "select", options: mapStatusOptions() }, commonText("contact_id", "Contact ID"), commonText("list_id", "List ID")];
    case "map.set_status":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, { key: "status", label: "Status", type: "select", options: mapStatusOptions() }];
    case "map.delete_pin":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, { key: "confirm_delete", label: "Confirm Delete", type: "boolean" }];
    case "map.add_to_list":
    case "map.move_to_list":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, commonText("list_id", "List ID"), commonText("list_name", "List Name")];
    case "map.remove_from_list":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }];
    case "map.link_contact":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, commonText("contact_id", "Contact ID")];
    case "map.unlink_contact":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }];
    case "map.create_contact":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, commonText("name", "Name"), commonText("phone", "Phone"), commonText("email", "Email"), { key: "tags", label: "Tags", type: "tag_list" }, commonText("job_type", "Job Type"), { key: "value_cents", label: "Value", type: "money" }];
    case "map.add_note":
    case "map.mark_visited":
    case "map.record_knock":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, commonText("note", "Note"), { key: "outcome_status", label: "Outcome Status", type: "select", options: mapStatusOptions() }];
    case "map.schedule_followup":
      return [{ key: "pin_id", label: "Pin", type: "map_pin" }, { key: "amount", label: "Amount", type: "number" }, { key: "unit", label: "Unit", type: "select", options: ["minutes", "hours", "days", "weeks"] }];
    case "map.add_to_route":
    case "route.add_pin":
      return [commonText("route_id", "Route ID"), { key: "pin_id", label: "Pin", type: "map_pin" }];
    case "route.create":
      return [commonText("name", "Route Name"), { key: "assigned_user_id", label: "Rep", type: "user" }, { key: "scheduled_date", label: "Date", type: "date" }, { key: "optimize", label: "Optimize Stops", type: "boolean" }];
    case "route.delete":
      return [commonText("route_id", "Route ID"), { key: "confirm_delete", label: "Confirm Delete", type: "boolean" }];
    case "route.add_stop":
      return [commonText("route_id", "Route ID"), commonText("pin_id", "Pin ID"), commonText("contact_id", "Contact ID"), commonText("job_id", "Job ID"), commonText("address", "Address"), { key: "latitude", label: "Latitude", type: "number" }, { key: "longitude", label: "Longitude", type: "number" }];
    case "route.remove_stop":
    case "route.complete_stop":
    case "route.skip_stop":
      return [commonText("stop_id", "Stop ID"), commonText("notes", "Notes")];
    case "route.add_contact":
      return [commonText("route_id", "Route ID"), commonText("contact_id", "Contact ID")];
    case "route.add_job":
      return [commonText("route_id", "Route ID"), commonText("job_id", "Job ID")];
    case "route.assign_user":
      return [commonText("route_id", "Route ID"), { key: "assigned_user_id", label: "Rep", type: "user" }];
    case "route.set_date":
      return [commonText("route_id", "Route ID"), { key: "scheduled_date", label: "Date", type: "date" }];
    case "route.optimize":
    case "route.mark_started":
    case "route.mark_completed":
      return [commonText("route_id", "Route ID")];
    case "employee.update_role":
      return [{ key: "employee_id", label: "Employee", type: "user" }, { key: "role", label: "Role", type: "select", options: ["employee", "employer"] }, { key: "confirm_sensitive_change", label: "Confirm Role Change", type: "boolean" }];
    case "employee.deactivate":
      return [{ key: "employee_id", label: "Employee", type: "user" }, { key: "confirm_deactivate", label: "Confirm Deactivate", type: "boolean" }];
    case "employee.reactivate":
    case "employee.send_push":
    case "employee.send_internal_message":
    case "employee.create_task":
      return [{ key: "employee_id", label: "Employee", type: "user" }, commonText("title", "Title"), commonText("body", "Message"), { key: "due_date", label: "Due Date", type: "datetime_expression" }];
    case "time_clock.create_review_task":
    case "time_clock.send_employee_reminder":
    case "time_clock.notify_manager":
      return [commonText("title", "Title"), commonText("body", "Message"), commonText("time_entry_id", "Time Entry ID")];
    case "time_clock.flag_for_review":
      return [commonText("time_entry_id", "Time Entry ID"), commonText("review_reason", "Review Reason")];
    case "time_clock.clear_review_flag":
      return [commonText("time_entry_id", "Time Entry ID")];
    case "measurement.create_record":
      return [commonText("name", "Name"), { key: "points", label: "Points", type: "json" }, { key: "units", label: "Units", type: "select", options: ["feet", "meters"] }, { key: "linked_contact_ids", label: "Contacts", type: "string_list" }];
    case "measurement.update_label":
      return [commonText("measurement_id", "Measurement ID"), commonText("name", "Name")];
    case "measurement.link_contact":
      return [commonText("measurement_id", "Measurement ID"), commonText("contact_id", "Contact ID")];
    case "contacts.search":
      return [{ key: "tags", label: "Tags", type: "tag_list" }, commonText("source", "Source"), { key: "limit", label: "Limit", type: "number" }];
    case "jobs.search":
      return [{ key: "start_after", label: "Start After", type: "datetime_expression" }, { key: "start_before", label: "Start Before", type: "datetime_expression" }, { key: "completed", label: "Completed", type: "boolean" }, commonText("contact_id", "Contact ID"), { key: "limit", label: "Limit", type: "number" }];
    case "tasks.search":
      return [{ key: "completed", label: "Completed", type: "boolean" }, { key: "overdue", label: "Overdue", type: "boolean" }, commonText("contact_id", "Contact ID"), { key: "limit", label: "Limit", type: "number" }];
    case "map.search_pins":
      return [{ key: "status", label: "Status", type: "select", options: ["lead", "won", "reloop", "later", "lost"] }, commonText("list_id", "List ID"), { key: "has_contact", label: "Has Contact", type: "boolean" }, { key: "limit", label: "Limit", type: "number" }];
    case "route.get_stops":
      return [commonText("route_id", "Route ID"), { key: "filter", label: "Stops", type: "select", options: ["all", "completed", "remaining", "skipped"] }];
    case "quotes.search":
      return [{ key: "status", label: "Status", type: "select", options: ["draft", "sent", "accepted", "declined", "expired", "converted"] }, commonText("contact_id", "Contact ID"), { key: "min_total_cents", label: "Minimum Total", type: "money" }, { key: "limit", label: "Limit", type: "number" }];
    case "payments.search":
      return [{ key: "status", label: "Status", type: "text" }, commonText("contact_id", "Contact ID"), commonText("service_plan_id", "Service Plan ID"), { key: "limit", label: "Limit", type: "number" }];
    case "service_plans.search":
      return [{ key: "status", label: "Status", type: "text" }, commonText("contact_id", "Contact ID"), { key: "limit", label: "Limit", type: "number" }];
    case "employees.search":
      return [{ key: "role", label: "Role", type: "select", options: ["any", "employee", "employer"] }, { key: "active", label: "Active", type: "boolean" }, { key: "limit", label: "Limit", type: "number" }];
    case "collection.filter":
      return [{ key: "collection", label: "Collection", type: "template" }, { key: "condition", label: "Filter", type: "condition" }];
    case "collection.map":
    case "object.build":
      return [{ key: "collection", label: "Collection", type: "template" }, { key: "mappings", label: "Mappings", type: "json" }];
    case "collection.sort":
      return [{ key: "collection", label: "Collection", type: "template" }, commonText("field", "Field"), { key: "direction", label: "Direction", type: "select", options: ["asc", "desc"] }, { key: "value_type", label: "Type", type: "select", options: ["string", "number", "date"] }];
    case "collection.limit":
      return [{ key: "collection", label: "Collection", type: "template" }, { key: "limit", label: "Limit", type: "number" }];
    case "collection.first":
    case "collection.last":
    case "collection.count":
    case "collection.flatten":
      return [{ key: "collection", label: "Collection", type: "template" }];
    case "collection.unique":
      return [{ key: "collection", label: "Collection", type: "template" }, commonText("identity_field", "Identity Field")];
    case "collection.concat":
      return [{ key: "collections", label: "Collections", type: "string_list" }];
    case "collection.contains":
      return [{ key: "collection", label: "Collection", type: "template" }, commonText("value", "Value"), commonText("field", "Field")];
    case "variable.increment":
      return [commonText("name", "Name"), { key: "amount", label: "Amount", type: "number" }];
    case "variable.append":
      return [commonText("name", "Name"), commonText("value", "Value"), { key: "dedupe", label: "Dedupe", type: "boolean" }];
    case "object.get":
      return [commonText("object", "Object"), commonText("path", "Path")];
    case "coalesce":
      return [{ key: "values", label: "Values", type: "string_list" }];
    case "math":
      return [commonText("a", "A"), { key: "operation", label: "Operation", type: "select", options: ["add", "subtract", "multiply", "divide", "percentage", "min", "max", "round", "floor", "ceil", "absolute"] }, commonText("b", "B")];
    case "text":
      return [{ key: "operation", label: "Operation", type: "select", options: ["join", "concat", "uppercase", "lowercase", "trim", "replace", "substring", "split", "length"] }, commonText("value", "Value"), commonText("delimiter", "Delimiter"), commonText("find", "Find"), commonText("replace", "Replace")];
    case "date":
      return [commonText("value", "Date"), { key: "operation", label: "Operation", type: "select", options: ["add", "subtract", "start_of_day", "end_of_day", "next_weekday", "format", "difference"] }, { key: "amount", label: "Amount", type: "number" }, { key: "unit", label: "Unit", type: "select", options: ["minutes", "hours", "days", "weeks", "months", "years"] }, commonText("other", "Other Date")];
    case "webhook.send":
      return [commonText("url", "URL"), { key: "method", label: "Method", type: "select", options: ["GET", "POST", "PUT", "PATCH", "DELETE"] }, { key: "headers", label: "Headers", type: "json" }, { key: "body", label: "JSON Body", type: "json" }];
    case "automation.start":
      return [commonText("automation_id", "Automation ID")];
    default:
      return [];
  }
}

function triggerConfigFields(key) {
  const sourceOptions = ["manual", "ios", "zapier", "meta", "webhook", "csv", "phone", "map", "schedule", "automation", "system", "other"];
  const fields = [];
  if (key.includes("field_changed") || /_(name|phone|email|address|value|job_type|source|u[1-5]|location|start|end|date|price|material_cost|color|contact|due|title)_changed$/.test(key)) {
    fields.push({ key: "field", label: "Field", type: key.startsWith("job.") ? "job_field" : key.startsWith("task.") ? "task_field" : "contact_field" });
    fields.push({ key: "from", label: "From", type: "text" });
    fields.push({ key: "to", label: "To", type: "text" });
  }
  if (key === "job.relative_time") {
    fields.push({ key: "reference", label: "Reference", type: "select", options: ["start", "end"] });
    fields.push({ key: "direction", label: "Direction", type: "select", options: ["before", "after"] });
    fields.push({ key: "amount", label: "Amount", type: "number" });
    fields.push({ key: "unit", label: "Unit", type: "select", options: ["minutes", "hours", "days", "weeks"] });
  }
  if (key === "quote.followup_due") {
    fields.push({ key: "basis", label: "After", type: "select", options: ["created", "sent"] });
    fields.push({ key: "amount", label: "Amount", type: "number" });
    fields.push({ key: "unit", label: "Unit", type: "select", options: ["minutes", "hours", "days", "weeks"] });
  }
  if (key === "service_plan.service_upcoming" || key === "service_plan.service_overdue") {
    fields.push({ key: "amount", label: "Amount", type: "number" });
    fields.push({ key: "unit", label: "Unit", type: "select", options: ["days", "weeks"] });
  }
  if (key === "map.pin_followup_due") {
    fields.push({ key: "basis", label: "After", type: "select", options: ["status_changed", "last_knock", "last_visit"] });
    fields.push({ key: "amount", label: "Amount", type: "number" });
    fields.push({ key: "unit", label: "Unit", type: "select", options: ["minutes", "hours", "days", "weeks"] });
  }
  if (key.startsWith("map.") || key.startsWith("canvass.")) {
    fields.push({ key: "statuses", label: "Statuses", type: "string_list", options: mapStatusOptions() });
    fields.push({ key: "from_status", label: "From Status", type: "select", options: ["any", ...mapStatusOptions()] });
    fields.push({ key: "to_status", label: "To Status", type: "select", options: ["any", ...mapStatusOptions()] });
    fields.push({ key: "list_id", label: "List", type: "map_list" });
    fields.push({ key: "known_contact", label: "Contact Link", type: "boolean" });
  }
  if (key.startsWith("route.")) fields.push({ key: "route_statuses", label: "Route Statuses", type: "string_list" }, { key: "assigned_user_id", label: "Assigned Rep", type: "user" });
  if (key.startsWith("employee.")) fields.push({ key: "employee_id", label: "Employee", type: "user" }, { key: "role", label: "Role", type: "select", options: ["employee", "employer"] }, { key: "active", label: "Active", type: "boolean" });
  if (key === "time_clock.shift_duration_reached" || key === "time_clock.overtime_threshold_reached" || key === "time_clock.missed_clock_out") {
    fields.push({ key: "amount", label: "Amount", type: "number" });
    fields.push({ key: "unit", label: "Unit", type: "select", options: ["minutes", "hours"] });
    fields.push({ key: "employee_id", label: "Employee", type: "user" });
  }
  if (key.startsWith("time_clock.") && !["time_clock.shift_duration_reached", "time_clock.overtime_threshold_reached", "time_clock.missed_clock_out"].includes(key)) fields.push({ key: "employee_id", label: "Employee", type: "user" });
  if (key.startsWith("quote.")) fields.push({ key: "statuses", label: "Statuses", type: "string_list" });
  if (key.startsWith("payment.")) fields.push({ key: "status", label: "Status", type: "text" }, { key: "min_amount_cents", label: "Minimum Amount", type: "money" }, { key: "max_amount_cents", label: "Maximum Amount", type: "money" });
  if (key.startsWith("service_plan.") || key.startsWith("subscription.")) fields.push({ key: "statuses", label: "Statuses", type: "string_list" });
  if (key.startsWith("job.")) fields.push({ key: "worker_user_ids", label: "Workers", type: "user_list" }, { key: "sales_user_ids", label: "Salespeople", type: "user_list" }, { key: "services", label: "Services", type: "string_list" });
  if (key.includes("tag_") || key.includes("tags_changed")) fields.push({ key: "tags", label: "Tags", type: "tag_list" }, { key: "tag_match", label: "Tag Match", type: "select", options: ["any", "one_of", "all"] });
  if (key.startsWith("lead.")) fields.push({ key: "sources", label: "Sources", type: "source_list", options: sourceOptions });
  if (key.includes("stage_") || key.includes("opportunity") || key.includes("pipeline.won") || key.includes("pipeline.lost") || key.includes("pipeline.reopened")) {
    fields.push({ key: "stage_ids", label: "Stages", type: "stage_list" });
    fields.push({ key: "from_stage_id", label: "From Stage", type: "stage" });
    fields.push({ key: "to_stage_id", label: "To Stage", type: "stage" });
  }
  fields.push({ key: "allow_automation_origin", label: "Allow events caused by automations", type: "boolean" });
  return fields;
}

function triggerIcon(key) {
  if (key.startsWith("map.") || key.startsWith("canvass.")) return "mappin";
  if (key.startsWith("route.")) return "point.topleft.down.curvedto.point.bottomright.up";
  if (key.startsWith("employee.")) return "person.2";
  if (key.startsWith("time_clock.")) return "clock";
  if (key.startsWith("measurement.")) return "ruler";
  if (key.startsWith("lead.")) return "person.badge.plus";
  if (key.includes("tag")) return "tag";
  if (key.startsWith("pipeline.won")) return "trophy";
  if (key.startsWith("pipeline.lost")) return "xmark.circle";
  if (key.startsWith("pipeline.")) return "arrow.right";
  if (key.startsWith("contact.")) return "person.crop.circle";
  return "bolt";
}

function actionIcon(key) {
  if (key.startsWith("map.")) return "mappin";
  if (key.startsWith("route.")) return "point.topleft.down.curvedto.point.bottomright.up";
  if (key.startsWith("employee.")) return "person.2";
  if (key.startsWith("time_clock.")) return "stopwatch";
  if (key.startsWith("measurement.")) return "ruler";
  if (key.includes("tag")) return "tag";
  if (key.includes("delete") || key.includes("remove") || key.includes("lost")) return "xmark.circle";
  if (key.includes("won")) return "trophy";
  if (key.startsWith("pipeline.")) return "arrow.right";
  if (key.startsWith("contact.")) return "person.crop.circle.badge.checkmark";
  if (key.startsWith("sms.")) return "message";
  if (key.startsWith("notification.")) return "bell";
  return "bolt";
}

function mapStatusOptions() {
  return ["lead", "won", "reloop", "later", "lost"];
}

function conditionFieldCatalog() {
  const textOps = ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "exists", "not_exists"];
  const numberOps = ["equals", "not_equals", "greater_than", "greater_or_equal", "less_than", "less_or_equal", "between", "exists", "not_exists"];
  const boolOps = ["is_true", "is_false"];
  const dateOps = ["before", "after", "between", "exists", "not_exists"];
  return [
    ["contact.id", "Contact ID", "Contact", "text", textOps],
    ["contact.exists", "Contact Exists", "Contact", "boolean", boolOps],
    ["contact.name", "Name", "Contact", "text", textOps],
    ["contact.phone", "Phone", "Contact", "text", textOps],
    ["contact.email", "Email", "Contact", "text", textOps],
    ["contact.address", "Address", "Contact", "text", textOps],
    ["contact.city", "City", "Contact", "text", textOps],
    ["contact.state", "State", "Contact", "text", textOps],
    ["contact.zip", "ZIP", "Contact", "text", textOps],
    ["contact.value", "Value", "Contact", "number", numberOps],
    ["contact.value_cents", "Value Cents", "Contact", "number", numberOps],
    ["contact.job_type", "Job Type", "Contact", "text", textOps],
    ["contact.source", "Source", "Contact", "text", textOps],
    ["contact.tags", "Tags", "Contact", "tags", ["contains", "not_contains", "exists", "not_exists"]],
    ["contact.u1", "Custom Field 1", "Contact", "text", textOps],
    ["contact.u2", "Custom Field 2", "Contact", "text", textOps],
    ["contact.u3", "Custom Field 3", "Contact", "text", textOps],
    ["contact.u4", "Custom Field 4", "Contact", "text", textOps],
    ["contact.u5", "Custom Field 5", "Contact", "text", textOps],
    ["contact.created_at", "Created At", "Contact", "date", dateOps],
    ["contact.updated_at", "Updated At", "Contact", "date", dateOps],
    ["contact.lat", "Latitude", "Contact", "number", numberOps],
    ["contact.lng", "Longitude", "Contact", "number", numberOps],
    ["contact.has_phone", "Has Phone", "Contact", "boolean", boolOps],
    ["contact.has_email", "Has Email", "Contact", "boolean", boolOps],
    ["contact.has_address", "Has Address", "Contact", "boolean", boolOps],
    ["contact.has_future_scheduled_job", "Has Future Job", "Relationships", "boolean", boolOps],
    ["contact.has_previous_completed_job", "Has Completed Job", "Relationships", "boolean", boolOps],
    ["contact.has_quote", "Has Quote", "Relationships", "boolean", boolOps],
    ["contact.has_unpaid_payment", "Has Unpaid Payment", "Relationships", "boolean", boolOps],
    ["contact.has_active_service_plan", "Has Active Service Plan", "Relationships", "boolean", boolOps],
    ["contact.exists_on_map", "Exists on Map", "Relationships", "boolean", boolOps],
    ["lead.source", "Lead Source", "Lead", "text", textOps],
    ["lead.external_id", "External Lead ID", "Lead", "text", textOps],
    ["lead.form_id", "Form ID", "Lead", "text", textOps],
    ["lead.page_id", "Page ID", "Lead", "text", textOps],
    ["lead.submitted_at", "Submitted At", "Lead", "date", dateOps],
    ["lead.has_lead_info", "Has Lead Info", "Lead", "boolean", boolOps],
    ["pipeline.has_opportunity", "Has Opportunity", "Pipeline", "boolean", boolOps],
    ["pipeline.stage_id", "Stage ID", "Pipeline", "stage", textOps],
    ["pipeline.stage_name", "Stage Name", "Pipeline", "text", textOps],
    ["pipeline.is_won", "Is Won", "Pipeline", "boolean", boolOps],
    ["pipeline.is_lost", "Is Lost", "Pipeline", "boolean", boolOps],
    ["pipeline.opportunity_value", "Opportunity Value", "Pipeline", "number", numberOps],
    ["pipeline.salesperson_id", "Salesperson ID", "Pipeline", "user", textOps],
    ["pipeline.salesperson_name", "Salesperson Name", "Pipeline", "text", textOps],
    ["pipeline.days_in_stage", "Days in Stage", "Pipeline", "number", numberOps],
    ["pipeline.reminder_exists", "Reminder Exists", "Pipeline", "boolean", boolOps],
    ["job.exists", "Job Exists", "Schedule & Jobs", "boolean", boolOps],
    ["job.id", "Job ID", "Schedule & Jobs", "text", textOps],
    ["job.contact_id", "Job Contact", "Schedule & Jobs", "text", textOps],
    ["job.start_at", "Job Start", "Schedule & Jobs", "date", dateOps],
    ["job.end_at", "Job End", "Schedule & Jobs", "date", dateOps],
    ["job.duration", "Job Duration", "Schedule & Jobs", "number", numberOps],
    ["job.price_cents", "Job Price", "Schedule & Jobs", "number", numberOps],
    ["job.material_cost_cents", "Material Cost", "Schedule & Jobs", "number", numberOps],
    ["job.color", "Job Color", "Schedule & Jobs", "text", textOps],
    ["job.finished_at", "Job Completed At", "Schedule & Jobs", "date", dateOps],
    ["job.completed", "Job Completed", "Schedule & Jobs", "boolean", boolOps],
    ["job.overdue", "Job Overdue", "Schedule & Jobs", "boolean", boolOps],
    ["job.service_items", "Job Services", "Schedule & Jobs", "text", textOps],
    ["job.worker_user_ids", "Worker IDs", "Schedule & Jobs", "text", textOps],
    ["job.sales_user_ids", "Salesperson IDs", "Schedule & Jobs", "text", textOps],
    ["job.has_workers", "Has Workers", "Schedule & Jobs", "boolean", boolOps],
    ["job.has_salesperson", "Has Salesperson", "Schedule & Jobs", "boolean", boolOps],
    ["task.exists", "Task Exists", "Tasks", "boolean", boolOps],
    ["task.title", "Task Title", "Tasks", "text", textOps],
    ["task.due_at", "Task Due", "Tasks", "date", dateOps],
    ["task.completed", "Task Completed", "Tasks", "boolean", boolOps],
    ["task.overdue", "Task Overdue", "Tasks", "boolean", boolOps],
    ["task.assigned_user", "Task Assignee", "Tasks", "user", textOps],
    ["task.subtask_count", "Subtask Count", "Tasks", "number", numberOps],
    ["task.completed_subtask_count", "Completed Subtasks", "Tasks", "number", numberOps],
    ["task.all_subtasks_completed", "All Subtasks Completed", "Tasks", "boolean", boolOps],
    ["routine.exists", "Routine Exists", "Routines", "boolean", boolOps],
    ["routine.active", "Routine Active", "Routines", "boolean", boolOps],
    ["routine.title", "Routine Title", "Routines", "text", textOps],
    ["routine.completed_today", "Completed Today", "Routines", "boolean", boolOps],
    ["routine.due_today", "Due Today", "Routines", "boolean", boolOps],
    ["routine.missed_today", "Missed Today", "Routines", "boolean", boolOps],
    ["customer_reminder.exists", "Reminder Exists", "Customer Reminders", "boolean", boolOps],
    ["customer_reminder.contact_id", "Reminder Contact", "Customer Reminders", "text", textOps],
    ["customer_reminder.due_at", "Reminder Due", "Customer Reminders", "date", dateOps],
    ["customer_reminder.completed", "Reminder Completed", "Customer Reminders", "boolean", boolOps],
    ["customer_reminder.overdue", "Reminder Overdue", "Customer Reminders", "boolean", boolOps],
    ["customer_reminder.title", "Reminder Title", "Customer Reminders", "text", textOps],
    ["quote.exists", "Quote Exists", "Quotes", "boolean", boolOps],
    ["quote.id", "Quote ID", "Quotes", "text", textOps],
    ["quote.contact_id", "Quote Contact", "Quotes", "text", textOps],
    ["quote.status", "Quote Status", "Quotes", "text", textOps],
    ["quote.subtotal_cents", "Quote Subtotal", "Quotes", "number", numberOps],
    ["quote.total_cents", "Quote Total", "Quotes", "number", numberOps],
    ["quote.line_item_count", "Quote Line Items", "Quotes", "number", numberOps],
    ["quote.created_at", "Quote Created At", "Quotes", "date", dateOps],
    ["quote.updated_at", "Quote Updated At", "Quotes", "date", dateOps],
    ["quote.expires_at", "Quote Expires At", "Quotes", "date", dateOps],
    ["quote.is_expired", "Quote Is Expired", "Quotes", "boolean", boolOps],
    ["quote.is_accepted", "Quote Is Accepted", "Quotes", "boolean", boolOps],
    ["quote.is_declined", "Quote Is Declined", "Quotes", "boolean", boolOps],
    ["quote.is_converted", "Quote Is Converted", "Quotes", "boolean", boolOps],
    ["invoice.exists", "Invoice Exists", "Invoices", "boolean", boolOps],
    ["invoice.status", "Invoice Status", "Invoices", "text", textOps],
    ["invoice.total_cents", "Invoice Total", "Invoices", "number", numberOps],
    ["invoice.due_at", "Invoice Due At", "Invoices", "date", dateOps],
    ["invoice.is_paid", "Invoice Paid", "Invoices", "boolean", boolOps],
    ["invoice.is_overdue", "Invoice Overdue", "Invoices", "boolean", boolOps],
    ["payment.exists", "Payment Exists", "Payments", "boolean", boolOps],
    ["payment.status", "Payment Status", "Payments", "text", textOps],
    ["payment.amount_cents", "Payment Amount", "Payments", "number", numberOps],
    ["payment.currency", "Payment Currency", "Payments", "text", textOps],
    ["payment.is_paid", "Payment Paid", "Payments", "boolean", boolOps],
    ["payment.is_failed", "Payment Failed", "Payments", "boolean", boolOps],
    ["payment.is_refunded", "Payment Refunded", "Payments", "boolean", boolOps],
    ["payment.contact_id", "Payment Contact", "Payments", "text", textOps],
    ["payment.service_plan_id", "Payment Service Plan", "Payments", "text", textOps],
    ["servicePlan.exists", "Service Plan Exists", "Service Plans", "boolean", boolOps],
    ["servicePlan.id", "Service Plan ID", "Service Plans", "text", textOps],
    ["servicePlan.contact_id", "Service Plan Contact", "Service Plans", "text", textOps],
    ["servicePlan.status", "Service Plan Status", "Service Plans", "text", textOps],
    ["servicePlan.active", "Service Plan Active", "Service Plans", "boolean", boolOps],
    ["servicePlan.paused", "Service Plan Paused", "Service Plans", "boolean", boolOps],
    ["servicePlan.canceled", "Service Plan Canceled", "Service Plans", "boolean", boolOps],
    ["servicePlan.price_cents", "Service Plan Price", "Service Plans", "number", numberOps],
    ["servicePlan.billing_interval", "Billing Interval", "Service Plans", "text", textOps],
    ["servicePlan.service_interval", "Service Interval", "Service Plans", "text", textOps],
    ["servicePlan.first_service_date", "First Service Date", "Service Plans", "date", dateOps],
    ["servicePlan.last_serviced_at", "Last Serviced At", "Service Plans", "date", dateOps],
    ["servicePlan.next_service_date", "Next Service Date", "Service Plans", "date", dateOps],
    ["servicePlan.service_count", "Service Count", "Service Plans", "number", numberOps],
    ["servicePlan.days_until_next_service", "Days Until Next Service", "Service Plans", "number", numberOps],
    ["servicePlan.is_due", "Service Plan Is Due", "Service Plans", "boolean", boolOps],
    ["servicePlan.is_overdue", "Service Plan Is Overdue", "Service Plans", "boolean", boolOps],
    ["servicePlan.subscription_status", "Subscription Status", "Subscriptions", "text", textOps],
    ["map.pin_exists", "Pin Exists", "Map & Canvassing", "boolean", boolOps],
    ["map.pin_id", "Pin ID", "Map & Canvassing", "text", textOps],
    ["map.status", "Pin Status", "Map & Canvassing", "text", textOps],
    ["map.list_id", "Map List", "Map & Canvassing", "text", textOps],
    ["map.list_name", "Map List Name", "Map & Canvassing", "text", textOps],
    ["map.address", "Pin Address", "Map & Canvassing", "text", textOps],
    ["map.latitude", "Latitude", "Map & Canvassing", "number", numberOps],
    ["map.longitude", "Longitude", "Map & Canvassing", "number", numberOps],
    ["map.contact_id", "Linked Contact", "Map & Canvassing", "text", textOps],
    ["map.has_contact", "Has Linked Contact", "Map & Canvassing", "boolean", boolOps],
    ["map.source", "Pin Source", "Map & Canvassing", "text", textOps],
    ["map.last_visit_at", "Last Visit", "Map & Canvassing", "date", dateOps],
    ["map.last_knock_at", "Last Knock", "Map & Canvassing", "date", dateOps],
    ["map.days_since_visit", "Days Since Visit", "Map & Canvassing", "number", numberOps],
    ["map.knock_count", "Knock Count", "Map & Canvassing", "number", numberOps],
    ["map.visit_count", "Visit Count", "Map & Canvassing", "number", numberOps],
    ["map.is_lead", "Is Lead", "Map & Canvassing", "boolean", boolOps],
    ["map.is_won", "Is Won", "Map & Canvassing", "boolean", boolOps],
    ["map.is_lost", "Is Lost", "Map & Canvassing", "boolean", boolOps],
    ["map.is_reloop", "Is Reloop", "Map & Canvassing", "boolean", boolOps],
    ["map.is_later", "Is Later", "Map & Canvassing", "boolean", boolOps],
    ["map.distance_miles", "Distance Miles", "Map & Canvassing", "number", numberOps],
    ["route.exists", "Route Exists", "Routes", "boolean", boolOps],
    ["route.status", "Route Status", "Routes", "text", textOps],
    ["route.stop_count", "Stop Count", "Routes", "number", numberOps],
    ["route.completed_stop_count", "Completed Stops", "Routes", "number", numberOps],
    ["route.remaining_stop_count", "Remaining Stops", "Routes", "number", numberOps],
    ["route.assigned_user_id", "Assigned Rep", "Routes", "user", textOps],
    ["route.scheduled_date", "Route Date", "Routes", "date", dateOps],
    ["route.all_stops_completed", "All Stops Completed", "Routes", "boolean", boolOps],
    ["routeStop.status", "Stop Status", "Routes", "text", textOps],
    ["routeStop.sort_order", "Stop Order", "Routes", "number", numberOps],
    ["routeStop.completed", "Stop Completed", "Routes", "boolean", boolOps],
    ["routeStop.skipped", "Stop Skipped", "Routes", "boolean", boolOps],
    ["employee.exists", "Employee Exists", "Employees & Team", "boolean", boolOps],
    ["employee.id", "Employee ID", "Employees & Team", "text", textOps],
    ["employee.name", "Employee Name", "Employees & Team", "text", textOps],
    ["employee.email", "Employee Email", "Employees & Team", "text", textOps],
    ["employee.role", "Employee Role", "Employees & Team", "text", textOps],
    ["employee.active", "Employee Active", "Employees & Team", "boolean", boolOps],
    ["employee.is_clocked_in", "Clocked In", "Employees & Team", "boolean", boolOps],
    ["employee.current_shift_duration", "Current Shift Minutes", "Employees & Team", "number", numberOps],
    ["employee.jobs_today", "Jobs Today", "Employees & Team", "number", numberOps],
    ["employee.completed_jobs_today", "Completed Jobs Today", "Employees & Team", "number", numberOps],
    ["employee.tasks_due_today", "Tasks Due Today", "Employees & Team", "number", numberOps],
    ["employee.overdue_tasks", "Overdue Tasks", "Employees & Team", "number", numberOps],
    ["employee.hours_today", "Hours Today", "Employees & Team", "number", numberOps],
    ["employee.hours_this_week", "Hours This Week", "Employees & Team", "number", numberOps],
    ["time_clock.employee_clocked_in", "Employee Clocked In", "Time Clock", "boolean", boolOps],
    ["time_clock.shift_duration_minutes", "Shift Duration Minutes", "Time Clock", "number", numberOps],
    ["time_clock.shift_duration_hours", "Shift Duration Hours", "Time Clock", "number", numberOps],
    ["time_clock.clock_in_at", "Clock In", "Time Clock", "date", dateOps],
    ["time_clock.clock_out_at", "Clock Out", "Time Clock", "date", dateOps],
    ["time_clock.needs_review", "Needs Review", "Time Clock", "boolean", boolOps],
    ["time_clock.job_id", "Linked Job", "Time Clock", "text", textOps],
    ["measurement.exists", "Measurement Exists", "Measurements", "boolean", boolOps],
    ["measurement.area", "Measurement Area", "Measurements", "number", numberOps],
    ["measurement.distance", "Measurement Distance", "Measurements", "number", numberOps],
    ["measurement.type", "Measurement Type", "Measurements", "text", textOps],
    ["measurement.contact_id", "Measurement Contact", "Measurements", "text", textOps],
    ["measurement.pin_id", "Measurement Pin", "Measurements", "text", textOps],
    ["time.now", "Current Time", "Time", "date", dateOps],
    ["time.day_of_week", "Day of Week", "Time", "number", numberOps],
    ["time.is_weekday", "Is Weekday", "Time", "boolean", boolOps],
    ["time.is_weekend", "Is Weekend", "Time", "boolean", boolOps],
    ["company.timezone", "Company Timezone", "Time", "text", textOps],
    ["sms.body", "SMS Body", "Cellular Messaging", "text", textOps],
    ["sms.direction", "SMS Direction", "Cellular Messaging", "text", textOps],
    ["sms.status", "SMS Status", "Cellular Messaging", "text", textOps],
    ["sms.external_number", "External Number", "Cellular Messaging", "text", textOps],
    ["sms.contact_exists", "SMS Contact Exists", "Cellular Messaging", "boolean", boolOps],
    ["sms.has_media", "SMS Has Media", "Cellular Messaging", "boolean", boolOps],
    ["sms.media_count", "SMS Media Count", "Cellular Messaging", "number", numberOps],
    ["sms.is_reply", "Is Reply", "Cellular Messaging", "boolean", boolOps],
    ["sms.reply_latency_seconds", "Reply Latency", "Cellular Messaging", "number", numberOps],
    ["sms.sms_opted_out", "SMS Opted Out", "Cellular Messaging", "boolean", boolOps],
    ["conversation.exists", "Conversation Exists", "Conversations", "boolean", boolOps],
    ["conversation.unread", "Conversation Unread", "Conversations", "boolean", boolOps],
    ["conversation.message_count", "Message Count", "Conversations", "number", numberOps],
    ["conversation.last_message_at", "Last Message At", "Conversations", "date", dateOps],
    ["conversation.last_direction", "Last Direction", "Conversations", "text", textOps],
    ["call.exists", "Call Exists", "Calls", "boolean", boolOps],
    ["call.direction", "Call Direction", "Calls", "text", textOps],
    ["call.status", "Call Status", "Calls", "text", textOps],
    ["call.disposition", "Call Disposition", "Calls", "text", textOps],
    ["call.duration_seconds", "Call Duration", "Calls", "number", numberOps],
    ["call.is_missed", "Call Missed", "Calls", "boolean", boolOps],
    ["call.is_after_hours", "Call After Hours", "Calls", "boolean", boolOps],
    ["call.contact_exists", "Call Contact Exists", "Calls", "boolean", boolOps],
    ["call.answered", "Call Answered", "Calls", "boolean", boolOps],
    ["call.failed", "Call Failed", "Calls", "boolean", boolOps],
    ["voicemail.exists", "Voicemail Exists", "Voicemail", "boolean", boolOps],
    ["voicemail.read", "Voicemail Read", "Voicemail", "boolean", boolOps],
    ["voicemail.duration", "Voicemail Duration", "Voicemail", "number", numberOps],
    ["voicemail.contact_exists", "Voicemail Contact Exists", "Voicemail", "boolean", boolOps],
    ["voicemail.external_number", "Voicemail External Number", "Voicemail", "text", textOps],
    ["voicemail.recording_status", "Recording Status", "Voicemail", "text", textOps],
    ["internal.message.body", "Internal Message Body", "Company Comms", "text", textOps],
    ["internal.message.has_attachment", "Internal Has Attachment", "Company Comms", "boolean", boolOps],
    ["internal.sender_id", "Internal Sender", "Company Comms", "user", textOps],
    ["internal.sender_name", "Internal Sender Name", "Company Comms", "text", textOps],
    ["internal.conversation_type", "Conversation Type", "Company Comms", "text", textOps],
    ["internal.channel_id", "Channel ID", "Company Comms", "text", textOps]
  ].map(([key, displayName, category, valueType, operators]) => ({ key, display_name: displayName, category, value_type: valueType, operators }));
}

function templateVariableCatalog() {
  return [
    "contact.name", "contact.phone", "contact.email", "contact.address", "contact.value", "contact.job_type", "contact.source",
    "contact.u1", "contact.u2", "contact.u3", "contact.u4", "contact.u5",
    "lead.source", "lead.external_id", "lead.form_id", "lead.page_id", "lead.submitted_at",
    "pipeline.stage_name", "pipeline.opportunity_value", "pipeline.salesperson_name",
    "job.id", "job.start_at", "job.end_at", "job.price_cents", "job.material_cost_cents", "job.service_items", "job.contact_id",
    "task.id", "task.title", "task.due_at",
    "routine.id", "routine.title",
    "customer_reminder.id", "customer_reminder.title", "customer_reminder.due_at",
    "quote.id", "quote.status", "quote.subtotal_cents", "quote.total_cents", "quote.expires_at",
    "invoice.id", "invoice.status", "invoice.total_cents", "invoice.due_at",
    "payment.id", "payment.status", "payment.amount_cents", "payment.currency",
    "servicePlan.id", "servicePlan.price_cents", "servicePlan.status", "servicePlan.billing_interval", "servicePlan.service_interval", "servicePlan.first_service_date", "servicePlan.last_serviced_at", "servicePlan.next_service_date", "servicePlan.service_count",
    "map.pin_id", "map.address", "map.status", "map.latitude", "map.longitude", "map.list_name", "map.last_visit_at", "map.last_knock_at",
    "route.id", "route.name", "route.stop_count", "route.remaining_stop_count", "route.assigned_user_name",
    "employee.id", "employee.name", "employee.role", "employee.email",
    "time_clock.clock_in", "time_clock.clock_out", "time_clock.duration_hours", "time_clock.employee_name",
    "sms.body", "sms.from", "sms.to", "sms.external_number", "sms.status",
    "conversation.last_message", "conversation.last_inbound_at", "conversation.last_outbound_at",
    "call.external_number", "call.duration_seconds", "call.status",
    "voicemail.external_number", "voicemail.duration",
    "internal.sender_name", "internal.message_body", "internal.channel_name",
    "company.name", "event.type", "event.payload.form_id", "event.payload.page_id", "variables.some_name"
  ].map((key) => ({ key, token: `{{${key}}}` }));
}

export async function installAutomationSystem(options) {
  ctx = options;
  await bootstrapAutomationSchema();
  await backfillFinancialAutomationSchedules();
  installAutomationRoutes();
  if (!options.disableProcessors) startAutomationProcessors();
}

export async function emitAutomationEvent(event) {
  if (!ctx?.pool || !event?.companyId || !event?.eventType) return null;
  const payload = safeJson(event.payload || {});
  if (Number(payload.automation_event_depth || 0) > AUTOMATION_LIMITS.maxChildDepth) {
    console.warn("[automations] event skipped at depth limit", { eventType: event.eventType, companyId: event.companyId });
    return null;
  }
  try {
    const { rows } = await ctx.pool.query(
      `INSERT INTO automation_events(
         id, company_id, event_type, subject_type, subject_id, actor_user_id, source, dedupe_key, payload, occurred_at, processing_status
       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,COALESCE($10::timestamptz, now()),'pending')
       ON CONFLICT (company_id, dedupe_key) WHERE dedupe_key IS NOT NULL
       DO UPDATE SET id = automation_events.id
       RETURNING id`,
      [
        randomUUID(),
        event.companyId,
        event.eventType,
        event.subjectType || null,
        event.subjectId ? String(event.subjectId) : null,
        event.actorUserId || null,
        event.source || "backend",
        event.dedupeKey || null,
        JSON.stringify(payload),
        event.occurredAt || null
      ]
    );
    setImmediate(() => processAutomationEvents().catch((e) => console.error("[automations] event processor wake failed", e?.message || e)));
    return rows[0]?.id || null;
  } catch (e) {
    console.error("[automations] emit failed", { eventType: event.eventType, code: e?.code, message: e?.message });
    return null;
  }
}

export async function syncAutomationSchedulesForJob(companyId, job) {
  if (!ctx?.pool || !companyId || !job?.id) return;
  await cancelScheduledForSubject(companyId, "job", job.id, ["job.start_time_reached", "job.overdue", "job.relative_time"]);
  if (job.finished_at) return;
  const start = new Date(job.start || job.start_at);
  const end = new Date(job.end || job.end_at);
  const sourceVersion = `${job.updated_at || ""}:${Number.isNaN(start.getTime()) ? job.start || job.start_at : start.toISOString()}:${Number.isNaN(end.getTime()) ? job.end || job.end_at : end.toISOString()}`;
  if (!Number.isNaN(start.getTime())) {
    await enqueueScheduledAutomationEvent({
      companyId, eventType: "job.start_time_reached", subjectType: "job", subjectId: job.id,
      scheduledFor: start, scheduleKey: `job.start_time_reached:${job.id}:${start.toISOString()}`, sourceVersion,
      payload: { job_id: job.id, contact_id: job.contact_id || null, start: start.toISOString(), end: Number.isNaN(end.getTime()) ? null : end.toISOString() }
    });
  }
  if (!Number.isNaN(end.getTime())) {
    await enqueueScheduledAutomationEvent({
      companyId, eventType: "job.overdue", subjectType: "job", subjectId: job.id,
      scheduledFor: end, scheduleKey: `job.overdue:${job.id}:${end.toISOString()}`, sourceVersion,
      payload: { job_id: job.id, contact_id: job.contact_id || null, start: Number.isNaN(start.getTime()) ? null : start.toISOString(), end: end.toISOString() }
    });
  }
  const relativeTriggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = 'job.relative_time'`,
    [companyId]
  )).rows;
  for (const trigger of relativeTriggers) {
    const config = trigger.config || {};
    const basis = config.reference === "end" ? end : start;
    if (Number.isNaN(basis.getTime())) continue;
    const ms = durationAmountMs(Number(config.amount || 0), config.unit || "minutes");
    const when = new Date(basis.getTime() + (config.direction === "after" ? ms : -ms));
    await enqueueScheduledAutomationEvent({
      companyId, eventType: "job.relative_time", subjectType: "job", subjectId: job.id,
      scheduledFor: when, scheduleKey: `job.relative_time:${trigger.id}:${job.id}:${basis.toISOString()}:${config.direction || "before"}:${config.amount || 0}:${config.unit || "minutes"}`,
      sourceVersion,
      payload: { job_id: job.id, contact_id: job.contact_id || null, trigger_node_id: trigger.id, reference: config.reference || "start", direction: config.direction || "before", amount: Number(config.amount || 0), unit: config.unit || "minutes", basis_time: basis.toISOString() }
    });
  }
}

export async function syncAutomationSchedulesForTask(companyId, task) {
  if (!ctx?.pool || !companyId || !task?.id) return;
  await cancelScheduledForSubject(companyId, "task", task.id, ["task.due", "task.overdue"]);
  if (task.completed || !task.due_date) return;
  const due = new Date(task.due_date);
  if (Number.isNaN(due.getTime())) return;
  const payload = { task_id: task.id, title: task.title, due_date: due.toISOString() };
  await enqueueScheduledAutomationEvent({ companyId, eventType: "task.due", subjectType: "task", subjectId: task.id, scheduledFor: due, scheduleKey: `task.due:${task.id}:${due.toISOString()}`, payload });
  await enqueueScheduledAutomationEvent({ companyId, eventType: "task.overdue", subjectType: "task", subjectId: task.id, scheduledFor: due, scheduleKey: `task.overdue:${task.id}:${due.toISOString()}`, payload });
}

export async function syncAutomationSchedulesForCustomerReminder(companyId, reminder) {
  if (!ctx?.pool || !companyId || !reminder?.id) return;
  await cancelScheduledForSubject(companyId, "customer_reminder", reminder.id, ["customer_reminder.due", "customer_reminder.overdue"]);
  if (reminder.completed || !reminder.due_date) return;
  const due = new Date(reminder.due_date);
  if (Number.isNaN(due.getTime())) return;
  const payload = { reminder_id: reminder.id, contact_id: reminder.contact_id || null, title: reminder.title || null, due_date: due.toISOString() };
  await enqueueScheduledAutomationEvent({ companyId, eventType: "customer_reminder.due", subjectType: "customer_reminder", subjectId: reminder.id, scheduledFor: due, scheduleKey: `customer_reminder.due:${reminder.id}:${due.toISOString()}`, payload });
  await enqueueScheduledAutomationEvent({ companyId, eventType: "customer_reminder.overdue", subjectType: "customer_reminder", subjectId: reminder.id, scheduledFor: due, scheduleKey: `customer_reminder.overdue:${reminder.id}:${due.toISOString()}`, payload });
}

export async function syncAutomationSchedulesForRoutine(companyId, routine) {
  if (!ctx?.pool || !companyId || !routine?.id) return;
  await cancelScheduledForSubject(companyId, "routine", routine.id, ["routine.due", "routine.missed", "routine.weekday_reached"]);
  if (!routine.enabled) return;
  const weekdays = Array.isArray(routine.weekdays) ? routine.weekdays.map(Number) : [];
  const baseTime = routine.time ? new Date(routine.time) : new Date();
  for (let offset = 0; offset < 14; offset++) {
    const date = new Date(Date.now() + offset * 86400000);
    const jsDay = date.getDay() + 1;
    if (weekdays.length && !weekdays.includes(jsDay)) continue;
    date.setUTCHours(baseTime.getUTCHours(), baseTime.getUTCMinutes(), 0, 0);
    const dayKey = date.toISOString().slice(0, 10);
    const payload = { routine_id: routine.id, title: routine.title, occurrence_date: dayKey };
    await enqueueScheduledAutomationEvent({ companyId, eventType: "routine.weekday_reached", subjectType: "routine", subjectId: routine.id, scheduledFor: date, scheduleKey: `routine.weekday_reached:${routine.id}:${dayKey}`, payload });
    await enqueueScheduledAutomationEvent({ companyId, eventType: "routine.due", subjectType: "routine", subjectId: routine.id, scheduledFor: date, scheduleKey: `routine.due:${routine.id}:${dayKey}`, payload });
    await enqueueScheduledAutomationEvent({ companyId, eventType: "routine.missed", subjectType: "routine", subjectId: routine.id, scheduledFor: new Date(date.getTime() + 24 * 3600000), scheduleKey: `routine.missed:${routine.id}:${dayKey}`, payload });
  }
}

export async function syncAutomationSchedulesForSmsOutbound(companyId, message) {
  if (!ctx?.pool || !companyId || !message?.id || !message.conversation_id) return;
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = 'sms.no_reply'`,
    [companyId]
  )).rows;
  for (const trigger of triggers) {
    const amount = Number(trigger.config?.amount || trigger.config?.after_amount || 0);
    const unit = trigger.config?.unit || trigger.config?.after_unit || "hours";
    if (amount <= 0) continue;
    const when = new Date(new Date(message.created_at || Date.now()).getTime() + durationAmountMs(amount, unit));
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: "sms.no_reply",
      subjectType: "sms_conversation",
      subjectId: message.conversation_id,
      scheduledFor: when,
      scheduleKey: `sms.no_reply:${trigger.id}:${message.conversation_id}:${message.id}:${amount}:${unit}`,
      payload: { trigger_node_id: trigger.id, conversation_id: message.conversation_id, message_id: message.id, contact_id: message.contact_id || null, external_number: message.external_phone_number || message.to_number || null, amount, unit }
    });
  }
}

export async function syncAutomationSchedulesForSmsConversationActivity(companyId, conversationId, lastMessage) {
  if (!ctx?.pool || !companyId || !conversationId) return;
  await cancelScheduledForSubject(companyId, "sms_conversation", conversationId, ["sms.conversation_inactive"]);
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = 'sms.conversation_inactive'`,
    [companyId]
  )).rows;
  for (const trigger of triggers) {
    const amount = Number(trigger.config?.amount || 0);
    const unit = trigger.config?.unit || "hours";
    if (amount <= 0) continue;
    const when = new Date(new Date(lastMessage?.created_at || Date.now()).getTime() + durationAmountMs(amount, unit));
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: "sms.conversation_inactive",
      subjectType: "sms_conversation",
      subjectId: conversationId,
      scheduledFor: when,
      scheduleKey: `sms.conversation_inactive:${trigger.id}:${conversationId}:${lastMessage?.id || Date.now()}:${amount}:${unit}`,
      payload: { trigger_node_id: trigger.id, conversation_id: conversationId, last_message_id: lastMessage?.id || null, amount, unit }
    });
  }
}

export async function cancelNoReplySchedulesForConversation(companyId, conversationId) {
  await cancelScheduledForSubject(companyId, "sms_conversation", conversationId, ["sms.no_reply"]);
}

export async function syncAutomationSchedulesForVoicemail(companyId, voicemail) {
  if (!ctx?.pool || !companyId || !voicemail?.id) return;
  await cancelScheduledForSubject(companyId, "voicemail", voicemail.id, ["voicemail.unread_for"]);
  if (voicemail.is_read || voicemail.deleted_at) return;
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = 'voicemail.unread_for'`,
    [companyId]
  )).rows;
  for (const trigger of triggers) {
    const amount = Number(trigger.config?.amount || 0);
    const unit = trigger.config?.unit || "hours";
    if (amount <= 0) continue;
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: "voicemail.unread_for",
      subjectType: "voicemail",
      subjectId: voicemail.id,
      scheduledFor: new Date(new Date(voicemail.created_at || Date.now()).getTime() + durationAmountMs(amount, unit)),
      scheduleKey: `voicemail.unread_for:${trigger.id}:${voicemail.id}:${amount}:${unit}`,
      payload: { trigger_node_id: trigger.id, voicemail_id: voicemail.id, contact_id: voicemail.contact_id || null, amount, unit }
    });
  }
}

export async function syncAutomationSchedulesForQuote(companyId, quote) {
  if (!ctx?.pool || !companyId || !quote?.id) return;
  await cancelScheduledForSubject(companyId, "quote", quote.id, ["quote.expired", "quote.followup_due"]);
  const status = String(quote.status || "draft");
  if (["accepted", "declined", "converted", "deleted"].includes(status)) return;
  const expiresAt = quote.expires_at ? new Date(quote.expires_at) : null;
  if (expiresAt && !Number.isNaN(expiresAt.getTime())) {
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: "quote.expired",
      subjectType: "quote",
      subjectId: quote.id,
      scheduledFor: expiresAt,
      scheduleKey: `quote.expired:${quote.id}:${expiresAt.toISOString()}`,
      sourceVersion: `${quote.updated_at || ""}:${status}:${expiresAt.toISOString()}`,
      payload: { quote_id: quote.id, contact_id: quote.contact_id || null, status, total_cents: quote.total_cents || 0, expires_at: expiresAt.toISOString() }
    });
  }
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = 'quote.followup_due'`,
    [companyId]
  )).rows;
  for (const trigger of triggers) {
    const basisName = trigger.config?.basis || trigger.config?.after || "created";
    const basisValue = basisName === "sent" ? quote.sent_at : quote.created_at;
    const basis = basisValue ? new Date(basisValue) : null;
    const amount = Number(trigger.config?.amount || 0);
    const unit = trigger.config?.unit || "days";
    if (!basis || Number.isNaN(basis.getTime()) || amount <= 0) continue;
    const when = new Date(basis.getTime() + durationAmountMs(amount, unit));
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: "quote.followup_due",
      subjectType: "quote",
      subjectId: quote.id,
      scheduledFor: when,
      scheduleKey: `quote.followup_due:${trigger.id}:${quote.id}:${basisName}:${basis.toISOString()}:${amount}:${unit}`,
      sourceVersion: `${quote.updated_at || ""}:${status}`,
      payload: { trigger_node_id: trigger.id, quote_id: quote.id, contact_id: quote.contact_id || null, status, total_cents: quote.total_cents || 0, basis: basisName, amount, unit }
    });
  }
}

export async function syncAutomationSchedulesForInvoice(companyId, invoice) {
  if (!ctx?.pool || !companyId || !invoice?.id) return;
  await cancelScheduledForSubject(companyId, "invoice", invoice.id, ["invoice.due", "invoice.overdue"]);
  if (!invoice.due_at || ["paid", "void", "deleted"].includes(String(invoice.status || ""))) return;
  const due = new Date(invoice.due_at);
  if (Number.isNaN(due.getTime())) return;
  const payload = { invoice_id: invoice.id, contact_id: invoice.contact_id || null, quote_id: invoice.quote_id || null, job_id: invoice.job_id || null, total_cents: invoice.total_cents || 0, status: invoice.status, due_at: due.toISOString() };
  await enqueueScheduledAutomationEvent({ companyId, eventType: "invoice.due", subjectType: "invoice", subjectId: invoice.id, scheduledFor: due, scheduleKey: `invoice.due:${invoice.id}:${due.toISOString()}`, sourceVersion: `${invoice.updated_at || ""}:${invoice.status}`, payload });
  await enqueueScheduledAutomationEvent({ companyId, eventType: "invoice.overdue", subjectType: "invoice", subjectId: invoice.id, scheduledFor: due, scheduleKey: `invoice.overdue:${invoice.id}:${due.toISOString()}`, sourceVersion: `${invoice.updated_at || ""}:${invoice.status}`, payload });
}

export async function syncAutomationSchedulesForServicePlan(companyId, plan) {
  if (!ctx?.pool || !companyId || !plan?.id) return;
  await cancelScheduledForSubject(companyId, "service_plan", plan.id, ["service_plan.service_upcoming", "service_plan.service_due", "service_plan.service_overdue"]);
  const status = String(plan.status || "");
  if (!["active", "payment_pending", "past_due"].includes(status) || !plan.next_service_date) return;
  const due = new Date(plan.next_service_date);
  if (Number.isNaN(due.getTime())) return;
  const cycleKey = due.toISOString().slice(0, 10);
  const basePayload = { service_plan_id: plan.id, contact_id: plan.contact_id || null, status, next_service_date: cycleKey, price_cents: plan.price_cents || 0 };
  await enqueueScheduledAutomationEvent({ companyId, eventType: "service_plan.service_due", subjectType: "service_plan", subjectId: plan.id, scheduledFor: due, scheduleKey: `service_plan.service_due:${plan.id}:${cycleKey}`, sourceVersion: `${plan.updated_at || ""}:${status}:${cycleKey}`, payload: basePayload });
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = ANY($2::text[])`,
    [companyId, ["service_plan.service_upcoming", "service_plan.service_overdue"]]
  )).rows;
  for (const trigger of triggers) {
    const key = trigger.config?.trigger_key;
    const amount = Number(trigger.config?.amount || (key === "service_plan.service_upcoming" ? 7 : 1));
    const unit = trigger.config?.unit || "days";
    if (amount <= 0) continue;
    const offset = durationAmountMs(amount, unit);
    const when = new Date(due.getTime() + (key === "service_plan.service_upcoming" ? -offset : offset));
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: key,
      subjectType: "service_plan",
      subjectId: plan.id,
      scheduledFor: when,
      scheduleKey: `${key}:${trigger.id}:${plan.id}:${cycleKey}:${amount}:${unit}`,
      sourceVersion: `${plan.updated_at || ""}:${status}:${cycleKey}`,
      payload: { ...basePayload, trigger_node_id: trigger.id, amount, unit }
    });
  }
}

export async function syncAutomationSchedulesForMapPin(companyId, pin, basis = "status_changed") {
  if (!ctx?.pool || !companyId || !pin?.id) return;
  await cancelScheduledForSubject(companyId, "map_pin", pin.id, ["map.pin_followup_due"]);
  if (["won", "lost"].includes(String(pin.status || ""))) return;
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = 'map.pin_followup_due'`,
    [companyId]
  )).rows;
  for (const trigger of triggers) {
    const config = trigger.config || {};
    const wantedBasis = config.basis || "status_changed";
    if (wantedBasis !== basis && basis !== "manual") continue;
    const amount = Number(config.amount || 0);
    const unit = config.unit || "days";
    if (amount <= 0) continue;
    const basisDate = wantedBasis === "last_knock" ? pin.last_knock_at : wantedBasis === "last_visit" ? pin.last_visit_at : pin.updated_at || new Date();
    const base = new Date(basisDate || Date.now());
    if (Number.isNaN(base.getTime())) continue;
    const when = new Date(base.getTime() + durationAmountMs(amount, unit));
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: "map.pin_followup_due",
      subjectType: "map_pin",
      subjectId: pin.id,
      scheduledFor: when,
      scheduleKey: `map.pin_followup_due:${trigger.id}:${pin.id}:${wantedBasis}:${base.toISOString()}:${amount}:${unit}`,
      sourceVersion: `${pin.updated_at || ""}:${pin.status || ""}:${pin.last_knock_at || ""}:${pin.last_visit_at || ""}`,
      payload: { trigger_node_id: trigger.id, pin_id: pin.id, status: pin.status || null, contact_id: pin.contact_id || null, basis: wantedBasis, amount, unit }
    });
  }
}

export async function syncAutomationSchedulesForTimeEntry(companyId, entry) {
  if (!ctx?.pool || !companyId || !entry?.id) return;
  await cancelScheduledForSubject(companyId, "time_entry", entry.id, ["time_clock.shift_duration_reached", "time_clock.overtime_threshold_reached", "time_clock.missed_clock_out"]);
  if (entry.end_at) return;
  const triggers = (await ctx.pool.query(
    `SELECT n.id, n.config
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1 AND d.status = 'published' AND n.config->>'trigger_key' = ANY($2::text[])`,
    [companyId, ["time_clock.shift_duration_reached", "time_clock.overtime_threshold_reached", "time_clock.missed_clock_out"]]
  )).rows;
  const start = new Date(entry.start_at);
  if (Number.isNaN(start.getTime())) return;
  for (const trigger of triggers) {
    if (trigger.config?.employee_id && trigger.config.employee_id !== entry.user_id) continue;
    const amount = Number(trigger.config?.amount || 0);
    const unit = trigger.config?.unit || "hours";
    if (amount <= 0) continue;
    const when = new Date(start.getTime() + durationAmountMs(amount, unit));
    await enqueueScheduledAutomationEvent({
      companyId,
      eventType: trigger.config?.trigger_key,
      subjectType: "time_entry",
      subjectId: entry.id,
      scheduledFor: when,
      scheduleKey: `${trigger.config?.trigger_key}:${trigger.id}:${entry.id}:${start.toISOString()}:${amount}:${unit}`,
      sourceVersion: `${entry.updated_at || ""}:${entry.end_at || ""}`,
      payload: { trigger_node_id: trigger.id, time_entry_id: entry.id, employee_id: entry.user_id, clock_in: start.toISOString(), amount, unit }
    });
  }
}

export async function cancelAutomationSchedulesForSubject(companyId, subjectType, subjectId) {
  if (!ctx?.pool || !companyId || !subjectType || !subjectId) return;
  await ctx.pool.query(
    `UPDATE automation_scheduled_events SET status = 'canceled', updated_at = now()
      WHERE company_id = $1 AND subject_type = $2 AND subject_id = $3 AND status = 'scheduled'`,
    [companyId, subjectType, String(subjectId)]
  );
}

async function enqueueScheduledAutomationEvent({ companyId, eventType, subjectType, subjectId, scheduledFor, scheduleKey, sourceVersion = null, payload = {} }) {
  await ctx.pool.query(
    `INSERT INTO automation_scheduled_events(company_id, event_type, subject_type, subject_id, scheduled_for, schedule_key, source_version, payload)
     VALUES($1,$2,$3,$4,$5::timestamptz,$6,$7,$8::jsonb)
     ON CONFLICT(company_id, schedule_key)
     DO UPDATE SET scheduled_for = EXCLUDED.scheduled_for, source_version = EXCLUDED.source_version, payload = EXCLUDED.payload, status = 'scheduled', updated_at = now()`,
    [companyId, eventType, subjectType, String(subjectId), scheduledFor.toISOString(), scheduleKey, sourceVersion, JSON.stringify(payload)]
  );
}

async function cancelScheduledForSubject(companyId, subjectType, subjectId, eventTypes) {
  await ctx.pool.query(
    `UPDATE automation_scheduled_events
        SET status = 'canceled', updated_at = now()
      WHERE company_id = $1 AND subject_type = $2 AND subject_id = $3 AND event_type = ANY($4::text[]) AND status = 'scheduled'`,
    [companyId, subjectType, String(subjectId), eventTypes]
  );
}

async function backfillFinancialAutomationSchedules() {
  try {
    const plans = (await ctx.pool.query(
      `SELECT * FROM service_plans
        WHERE company_id IS NOT NULL
          AND status IN ('active','payment_pending','past_due')
          AND next_service_date IS NOT NULL
          AND next_service_date >= CURRENT_DATE
        LIMIT 1000`
    )).rows;
    for (const plan of plans) {
      await syncAutomationSchedulesForServicePlan(plan.company_id, plan);
    }
  } catch (e) {
    console.error("[automations] financial schedule backfill failed", e?.message || e);
  }
}

function durationAmountMs(amount, unit) {
  const n = Math.max(0, Number(amount || 0));
  if (String(unit).startsWith("week")) return n * 7 * 86400000;
  if (String(unit).startsWith("day")) return n * 86400000;
  if (String(unit).startsWith("hour")) return n * 3600000;
  return n * 60000;
}

async function bootstrapAutomationSchema() {
  await ctx.pool.query(`
    CREATE TABLE IF NOT EXISTS automation_folders (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_folders_company_sort_idx ON automation_folders(company_id, sort_order, name);

    CREATE TABLE IF NOT EXISTS automation_definitions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      folder_id UUID REFERENCES automation_folders(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      active_version_id UUID,
      draft_version_id UUID,
      pause_until TIMESTAMPTZ,
      allow_manual_trigger BOOLEAN NOT NULL DEFAULT true,
      max_parallel_runs_per_subject INTEGER,
      max_active_runs INTEGER,
      max_active_runs_per_subject INTEGER,
      concurrency_policy TEXT NOT NULL DEFAULT 'queue',
      subject_concurrency_policy TEXT NOT NULL DEFAULT 'queue',
      reentry_mode TEXT NOT NULL DEFAULT 'after_previous_completion',
      cooldown_seconds INTEGER,
      cooldown_basis TEXT NOT NULL DEFAULT 'completed_at',
      failure_auto_pause_enabled BOOLEAN NOT NULL DEFAULT false,
      failure_auto_pause_threshold INTEGER NOT NULL DEFAULT 10,
      failure_auto_pause_window_seconds INTEGER NOT NULL DEFAULT 3600,
      risk_fingerprint TEXT,
      risk_acknowledged_at TIMESTAMPTZ,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS max_active_runs INTEGER;
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS max_active_runs_per_subject INTEGER;
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS concurrency_policy TEXT NOT NULL DEFAULT 'queue';
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS subject_concurrency_policy TEXT NOT NULL DEFAULT 'queue';
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS cooldown_basis TEXT NOT NULL DEFAULT 'completed_at';
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS failure_auto_pause_enabled BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS failure_auto_pause_threshold INTEGER NOT NULL DEFAULT 10;
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS failure_auto_pause_window_seconds INTEGER NOT NULL DEFAULT 3600;
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS risk_fingerprint TEXT;
    ALTER TABLE automation_definitions ADD COLUMN IF NOT EXISTS risk_acknowledged_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS automation_definitions_company_status_idx ON automation_definitions(company_id, status);
    CREATE INDEX IF NOT EXISTS automation_definitions_active_version_idx ON automation_definitions(active_version_id);
    CREATE INDEX IF NOT EXISTS automation_definitions_draft_version_idx ON automation_definitions(draft_version_id);

    CREATE TABLE IF NOT EXISTS automation_versions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      automation_id UUID NOT NULL REFERENCES automation_definitions(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      version_number INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      published_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(automation_id, version_number)
    );
    CREATE INDEX IF NOT EXISTS automation_versions_company_status_idx ON automation_versions(company_id, status);

    CREATE TABLE IF NOT EXISTS automation_nodes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      version_id UUID NOT NULL REFERENCES automation_versions(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      node_key TEXT NOT NULL,
      node_type TEXT NOT NULL,
      category TEXT,
      title TEXT,
      config JSONB NOT NULL DEFAULT '{}'::jsonb,
      position_x DOUBLE PRECISION NOT NULL DEFAULT 0,
      position_y DOUBLE PRECISION NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(version_id, node_key)
    );
    CREATE INDEX IF NOT EXISTS automation_nodes_version_type_idx ON automation_nodes(version_id, node_type);
    CREATE INDEX IF NOT EXISTS automation_nodes_trigger_event_idx ON automation_nodes(company_id, ((config->>'trigger_key'))) WHERE node_type = 'trigger';

    CREATE TABLE IF NOT EXISTS automation_edges (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      version_id UUID NOT NULL REFERENCES automation_versions(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      source_node_id UUID NOT NULL REFERENCES automation_nodes(id) ON DELETE CASCADE,
      target_node_id UUID NOT NULL REFERENCES automation_nodes(id) ON DELETE CASCADE,
      source_port TEXT,
      target_port TEXT,
      label TEXT,
      priority INTEGER NOT NULL DEFAULT 0,
      config JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_edges_version_source_idx ON automation_edges(version_id, source_node_id, priority);
    CREATE INDEX IF NOT EXISTS automation_edges_version_target_idx ON automation_edges(version_id, target_node_id);

    CREATE TABLE IF NOT EXISTS automation_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      subject_type TEXT,
      subject_id TEXT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      source TEXT NOT NULL DEFAULT 'backend',
      dedupe_key TEXT,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      processed_at TIMESTAMPTZ,
      processing_status TEXT NOT NULL DEFAULT 'pending',
      error TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TIMESTAMPTZ,
      locked_at TIMESTAMPTZ,
      locked_by TEXT,
      failed_at TIMESTAMPTZ
    );
    ALTER TABLE automation_events ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE automation_events ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
    ALTER TABLE automation_events ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
    ALTER TABLE automation_events ADD COLUMN IF NOT EXISTS locked_by TEXT;
    ALTER TABLE automation_events ADD COLUMN IF NOT EXISTS failed_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS automation_events_company_type_idx ON automation_events(company_id, event_type, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS automation_events_status_idx ON automation_events(processing_status, processed_at, created_at);
    CREATE INDEX IF NOT EXISTS automation_events_retry_idx ON automation_events(processing_status, next_attempt_at, created_at);
    CREATE INDEX IF NOT EXISTS automation_events_occurred_idx ON automation_events(occurred_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS automation_events_company_dedupe_uidx ON automation_events(company_id, dedupe_key) WHERE dedupe_key IS NOT NULL;

    CREATE TABLE IF NOT EXISTS automation_runs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      automation_id UUID NOT NULL REFERENCES automation_definitions(id) ON DELETE CASCADE,
      automation_version_id UUID NOT NULL REFERENCES automation_versions(id) ON DELETE RESTRICT,
      trigger_event_id UUID REFERENCES automation_events(id) ON DELETE SET NULL,
      subject_type TEXT,
      subject_id TEXT,
      status TEXT NOT NULL DEFAULT 'queued',
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      current_node_count INTEGER NOT NULL DEFAULT 0,
      error_code TEXT,
      error_message TEXT,
      depth INTEGER NOT NULL DEFAULT 0,
      parent_run_id UUID REFERENCES automation_runs(id) ON DELETE SET NULL,
      parent_node_id UUID,
      root_run_id UUID REFERENCES automation_runs(id) ON DELETE SET NULL,
      reentry_key TEXT,
      stop_reason TEXT,
      stop_condition_key TEXT,
      recovered_from_run_id UUID,
      recovered_from_run_node_id UUID,
      recovery_start_node_id UUID,
      recovery_scope_key TEXT,
      active_execution_ms BIGINT NOT NULL DEFAULT 0,
      customer_message_count INTEGER NOT NULL DEFAULT 0,
      internal_message_count INTEGER NOT NULL DEFAULT 0,
      webhook_action_count INTEGER NOT NULL DEFAULT 0,
      child_run_count INTEGER NOT NULL DEFAULT 0,
      total_iteration_count INTEGER NOT NULL DEFAULT 0,
      manual_started_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      dry_run BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS parent_node_id UUID;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS reentry_key TEXT;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS stop_reason TEXT;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS stop_condition_key TEXT;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS recovered_from_run_id UUID;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS recovered_from_run_node_id UUID;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS recovery_start_node_id UUID;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS recovery_scope_key TEXT;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS active_execution_ms BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS customer_message_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS internal_message_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS webhook_action_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS child_run_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE automation_runs ADD COLUMN IF NOT EXISTS total_iteration_count INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS automation_runs_company_status_idx ON automation_runs(company_id, status, created_at DESC);
    CREATE INDEX IF NOT EXISTS automation_runs_automation_idx ON automation_runs(automation_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS automation_runs_subject_idx ON automation_runs(company_id, automation_id, subject_type, subject_id);
    CREATE INDEX IF NOT EXISTS automation_runs_reentry_idx ON automation_runs(company_id, automation_id, reentry_key, status);

    CREATE TABLE IF NOT EXISTS automation_run_nodes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      node_id UUID REFERENCES automation_nodes(id) ON DELETE SET NULL,
      node_key TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      scope_key TEXT NOT NULL DEFAULT 'root',
      attempt_number INTEGER NOT NULL DEFAULT 1,
      input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
      output_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
      error_code TEXT,
      error_message TEXT,
      error_class TEXT,
      retryable BOOLEAN,
      next_retry_at TIMESTAMPTZ,
      locked_at TIMESTAMPTZ,
      locked_by TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE automation_run_nodes ADD COLUMN IF NOT EXISTS scope_key TEXT NOT NULL DEFAULT 'root';
    ALTER TABLE automation_run_nodes ADD COLUMN IF NOT EXISTS error_class TEXT;
    ALTER TABLE automation_run_nodes ADD COLUMN IF NOT EXISTS retryable BOOLEAN;
    ALTER TABLE automation_run_nodes ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
    ALTER TABLE automation_run_nodes ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
    ALTER TABLE automation_run_nodes ADD COLUMN IF NOT EXISTS locked_by TEXT;
    CREATE INDEX IF NOT EXISTS automation_run_nodes_run_idx ON automation_run_nodes(run_id, created_at);
    CREATE INDEX IF NOT EXISTS automation_run_nodes_node_idx ON automation_run_nodes(run_id, node_key, attempt_number);
    CREATE INDEX IF NOT EXISTS automation_run_nodes_scope_idx ON automation_run_nodes(run_id, node_key, scope_key, status);

    CREATE TABLE IF NOT EXISTS automation_waits (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      node_id UUID REFERENCES automation_nodes(id) ON DELETE SET NULL,
      wait_type TEXT NOT NULL,
      resume_at TIMESTAMPTZ,
      event_type TEXT,
      event_filter JSONB,
      timeout_at TIMESTAMPTZ,
      status TEXT NOT NULL DEFAULT 'waiting',
      scope_key TEXT NOT NULL DEFAULT 'root',
      resume_port TEXT,
      matched_event JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE automation_waits ADD COLUMN IF NOT EXISTS scope_key TEXT NOT NULL DEFAULT 'root';
    ALTER TABLE automation_waits ADD COLUMN IF NOT EXISTS resume_port TEXT;
    ALTER TABLE automation_waits ADD COLUMN IF NOT EXISTS matched_event JSONB;
    CREATE INDEX IF NOT EXISTS automation_waits_due_idx ON automation_waits(status, resume_at) WHERE status = 'waiting' AND resume_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS automation_waits_timeout_idx ON automation_waits(status, timeout_at) WHERE status = 'waiting' AND timeout_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS automation_waits_event_idx ON automation_waits(status, event_type) WHERE status = 'waiting' AND event_type IS NOT NULL;
    CREATE INDEX IF NOT EXISTS automation_waits_scope_idx ON automation_waits(run_id, node_id, scope_key, status);

    CREATE TABLE IF NOT EXISTS automation_variables (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      value JSONB NOT NULL DEFAULT 'null'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(run_id, name)
    );

    CREATE TABLE IF NOT EXISTS automation_run_iterations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      foreach_node_id UUID REFERENCES automation_nodes(id) ON DELETE SET NULL,
      foreach_node_key TEXT NOT NULL,
      parent_scope_key TEXT NOT NULL DEFAULT 'root',
      scope_key TEXT NOT NULL,
      iteration_key TEXT NOT NULL,
      item_index INTEGER NOT NULL,
      item_count INTEGER NOT NULL,
      item_data JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'queued',
      error TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      failed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(run_id, foreach_node_id, parent_scope_key, iteration_key)
    );
    ALTER TABLE automation_run_iterations ADD COLUMN IF NOT EXISTS retry_of_iteration_id UUID;
    ALTER TABLE automation_run_iterations ADD COLUMN IF NOT EXISTS attempt_number INTEGER NOT NULL DEFAULT 1;
    CREATE INDEX IF NOT EXISTS automation_run_iterations_status_idx ON automation_run_iterations(run_id, foreach_node_id, parent_scope_key, status, item_index);
    CREATE INDEX IF NOT EXISTS automation_run_iterations_scope_idx ON automation_run_iterations(run_id, scope_key);

    CREATE TABLE IF NOT EXISTS automation_merge_arrivals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      merge_node_id UUID REFERENCES automation_nodes(id) ON DELETE SET NULL,
      scope_key TEXT NOT NULL DEFAULT 'root',
      arrival_key TEXT NOT NULL,
      source_node_id UUID,
      source_port TEXT,
      arrived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      released_at TIMESTAMPTZ,
      UNIQUE(run_id, merge_node_id, scope_key, arrival_key)
    );
    CREATE INDEX IF NOT EXISTS automation_merge_arrivals_lookup_idx ON automation_merge_arrivals(run_id, merge_node_id, scope_key, released_at);

    CREATE TABLE IF NOT EXISTS automation_run_goals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      node_id UUID REFERENCES automation_nodes(id) ON DELETE SET NULL,
      goal_key TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      scope_key TEXT NOT NULL DEFAULT 'root',
      reached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(run_id, node_id, scope_key, goal_key)
    );
    CREATE INDEX IF NOT EXISTS automation_run_goals_run_idx ON automation_run_goals(run_id, reached_at);

    CREATE TABLE IF NOT EXISTS automation_run_node_attempts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      run_node_id UUID REFERENCES automation_run_nodes(id) ON DELETE SET NULL,
      node_id UUID,
      node_key TEXT NOT NULL,
      scope_key TEXT NOT NULL DEFAULT 'root',
      attempt_number INTEGER NOT NULL,
      status TEXT NOT NULL,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      error_code TEXT,
      error_class TEXT,
      error_message TEXT,
      retryable BOOLEAN,
      next_retry_at TIMESTAMPTZ,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_run_node_attempts_run_idx ON automation_run_node_attempts(run_id, node_key, scope_key, attempt_number);

    CREATE TABLE IF NOT EXISTS automation_run_monitors (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      automation_version_id UUID NOT NULL REFERENCES automation_versions(id) ON DELETE CASCADE,
      monitor_type TEXT NOT NULL,
      event_type TEXT NOT NULL,
      monitor_key TEXT NOT NULL,
      mode TEXT NOT NULL DEFAULT 'any',
      behavior TEXT NOT NULL DEFAULT 'stop',
      match_subject_type TEXT,
      match_subject_id TEXT,
      config JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'active',
      matched_event_id UUID REFERENCES automation_events(id) ON DELETE SET NULL,
      matched_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(run_id, monitor_type, monitor_key, event_type)
    );
    CREATE INDEX IF NOT EXISTS automation_run_monitors_event_idx ON automation_run_monitors(event_type, status, match_subject_type, match_subject_id);
    CREATE INDEX IF NOT EXISTS automation_run_monitors_run_idx ON automation_run_monitors(run_id, status);

    CREATE TABLE IF NOT EXISTS automation_dead_letters (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      source_type TEXT NOT NULL,
      source_id UUID,
      automation_id UUID,
      run_id UUID,
      event_type TEXT,
      subject_type TEXT,
      subject_id TEXT,
      attempts INTEGER NOT NULL DEFAULT 0,
      error_code TEXT,
      error_message TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      failed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      dismissed_at TIMESTAMPTZ,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    );
    CREATE INDEX IF NOT EXISTS automation_dead_letters_company_status_idx ON automation_dead_letters(company_id, status, failed_at DESC);

    CREATE TABLE IF NOT EXISTS automation_action_effects (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      node_id UUID,
      scope_key TEXT NOT NULL DEFAULT 'root',
      effect_key TEXT NOT NULL,
      effect_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'started',
      external_id TEXT,
      result JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(run_id, node_id, scope_key, effect_key)
    );
    CREATE INDEX IF NOT EXISTS automation_action_effects_lookup_idx ON automation_action_effects(run_id, node_id, scope_key, effect_type, status);

    CREATE TABLE IF NOT EXISTS automation_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      automation_id UUID REFERENCES automation_definitions(id) ON DELETE CASCADE,
      run_id UUID REFERENCES automation_runs(id) ON DELETE CASCADE,
      node_id UUID,
      level TEXT NOT NULL DEFAULT 'info',
      event TEXT NOT NULL,
      message TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_logs_run_date_idx ON automation_logs(run_id, created_at);
    CREATE INDEX IF NOT EXISTS automation_logs_company_date_idx ON automation_logs(company_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS contact_activities (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      contact_id TEXT NOT NULL,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      activity_type TEXT NOT NULL DEFAULT 'note',
      body TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'automation',
      automation_run_id UUID REFERENCES automation_runs(id) ON DELETE SET NULL,
      automation_node_id UUID,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS contact_activities_company_contact_idx ON contact_activities(company_id, contact_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS automation_scheduled_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      subject_type TEXT,
      subject_id TEXT,
      scheduled_for TIMESTAMPTZ NOT NULL,
      schedule_key TEXT NOT NULL,
      source_version TEXT,
      status TEXT NOT NULL DEFAULT 'scheduled',
      source TEXT NOT NULL DEFAULT 'automation_scheduler',
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TIMESTAMPTZ,
      error TEXT,
      locked_at TIMESTAMPTZ,
      locked_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      fired_at TIMESTAMPTZ,
      UNIQUE(company_id, schedule_key)
    );
    ALTER TABLE automation_scheduled_events ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE automation_scheduled_events ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
    ALTER TABLE automation_scheduled_events ADD COLUMN IF NOT EXISTS error TEXT;
    ALTER TABLE automation_scheduled_events ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
    ALTER TABLE automation_scheduled_events ADD COLUMN IF NOT EXISTS locked_by TEXT;
    CREATE INDEX IF NOT EXISTS automation_scheduled_events_due_idx ON automation_scheduled_events(status, scheduled_for);
    CREATE INDEX IF NOT EXISTS automation_scheduled_events_retry_idx ON automation_scheduled_events(status, next_attempt_at, scheduled_for);
    CREATE INDEX IF NOT EXISTS automation_scheduled_events_subject_idx ON automation_scheduled_events(company_id, subject_type, subject_id, status);

    CREATE TABLE IF NOT EXISTS phone_opt_outs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      normalized_phone TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'sms',
      status TEXT NOT NULL DEFAULT 'opted_out',
      source TEXT NOT NULL DEFAULT 'twilio',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, normalized_phone, channel)
    );
    CREATE INDEX IF NOT EXISTS phone_opt_outs_company_phone_idx ON phone_opt_outs(company_id, normalized_phone, status);

    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS list_id UUID;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS last_visit_at TIMESTAMPTZ;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS last_knock_at TIMESTAMPTZ;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS visit_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS knock_count INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS map_pins_status_idx ON map_pins(status);
    CREATE INDEX IF NOT EXISTS map_pins_list_idx ON map_pins(list_id);

    CREATE TABLE IF NOT EXISTS map_lists (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, name)
    );
    CREATE INDEX IF NOT EXISTS map_lists_company_name_idx ON map_lists(company_id, name);

    CREATE TABLE IF NOT EXISTS map_pin_activities (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      pin_id TEXT NOT NULL REFERENCES map_pins(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      activity_type TEXT NOT NULL,
      old_status TEXT,
      new_status TEXT,
      note TEXT,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      source TEXT NOT NULL DEFAULT 'automation',
      automation_run_id UUID REFERENCES automation_runs(id) ON DELETE SET NULL,
      automation_node_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS map_pin_activities_pin_idx ON map_pin_activities(company_id, pin_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS field_routes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      scheduled_date DATE,
      status TEXT NOT NULL DEFAULT 'draft',
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS field_routes_company_status_idx ON field_routes(company_id, status, scheduled_date);
    CREATE INDEX IF NOT EXISTS field_routes_assigned_idx ON field_routes(company_id, assigned_user_id, scheduled_date);

    CREATE TABLE IF NOT EXISTS field_route_stops (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      route_id UUID NOT NULL REFERENCES field_routes(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      pin_id TEXT,
      contact_id TEXT,
      job_id UUID,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      address TEXT NOT NULL DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      arrived_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(route_id, pin_id),
      UNIQUE(route_id, contact_id),
      UNIQUE(route_id, job_id)
    );
    CREATE INDEX IF NOT EXISTS field_route_stops_route_order_idx ON field_route_stops(route_id, sort_order);
    CREATE INDEX IF NOT EXISTS field_route_stops_company_status_idx ON field_route_stops(company_id, status);

    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS needs_review BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS review_reason TEXT;
    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS job_id UUID;
    CREATE INDEX IF NOT EXISTS time_clock_entries_review_idx ON time_clock_entries(company_id, needs_review) WHERE needs_review = true;

    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft';
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS accepted_at TIMESTAMPTZ;
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS declined_at TIMESTAMPTZ;
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS converted_job_id UUID;
    CREATE INDEX IF NOT EXISTS quotes_company_status_idx ON quotes(company_id, status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS quotes_expires_idx ON quotes(company_id, expires_at) WHERE expires_at IS NOT NULL;

    CREATE TABLE IF NOT EXISTS invoices (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      contact_id UUID,
      job_id UUID,
      quote_id UUID,
      status TEXT NOT NULL DEFAULT 'draft',
      line_items JSONB NOT NULL DEFAULT '[]'::jsonb,
      subtotal_cents INTEGER NOT NULL DEFAULT 0,
      total_cents INTEGER NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'usd',
      due_at TIMESTAMPTZ,
      issued_at TIMESTAMPTZ,
      paid_at TIMESTAMPTZ,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS invoices_company_status_idx ON invoices(company_id, status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS invoices_contact_idx ON invoices(company_id, contact_id);
    CREATE INDEX IF NOT EXISTS invoices_due_idx ON invoices(company_id, due_at) WHERE due_at IS NOT NULL;

    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automated_customer_messages_enabled BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automations_enabled BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_emergency_stopped_at TIMESTAMPTZ;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_sms_default_business_hours_policy TEXT NOT NULL DEFAULT 'send_immediately';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_sms_max_per_contact_hour INTEGER NOT NULL DEFAULT 6;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_sms_max_per_contact_day INTEGER NOT NULL DEFAULT 20;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_max_active_runs INTEGER NOT NULL DEFAULT 100;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_run_starts_per_minute INTEGER NOT NULL DEFAULT 120;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_node_executions_per_minute INTEGER NOT NULL DEFAULT 2000;
  `);
}

function installAutomationRoutes() {
  const { app, authRequired, requireEmployer } = ctx;

  app.get("/api/automations/catalog", authRequired, requireEmployer, (_req, res) => {
    res.json({
      triggers: triggerCatalog,
      actions: actionCatalog,
      condition_fields: conditionFieldCatalog(),
      template_variables: templateVariableCatalog(),
      sources: ["manual", "ios", "zapier", "meta", "webhook", "csv", "phone", "map", "schedule", "automation", "system", "other"],
      logic_nodes: [
        { key: "condition", display_name: "Condition", category: "Logic", description: "Routes to true or false ports.", outputs: ["true", "false"], config_fields: [{ key: "condition", type: "condition" }] },
        { key: "branch", display_name: "Branch", category: "Logic", description: "Routes by resolved value to named ports.", outputs: ["default"], config_fields: [{ key: "input", type: "template" }, { key: "branches", type: "string_list" }] },
        { key: "switch", display_name: "Switch", category: "Logic", description: "Routes by ordered deterministic cases.", outputs: ["default"], dynamic_ports: true, config_fields: [{ key: "input", type: "template" }, { key: "cases", type: "switch_cases" }] },
        { key: "parallel", display_name: "Parallel", category: "Flow Control", description: "Activates every configured output path.", outputs: ["path_a", "path_b"], dynamic_ports: true, config_fields: [{ key: "paths", type: "port_list" }] },
        { key: "merge", display_name: "Merge", category: "Flow Control", description: "Waits for Any, All, or First inbound path.", outputs: ["default"], config_fields: [{ key: "mode", type: "select", options: ["any", "all", "first"] }] },
        { key: "foreach", display_name: "For Each", category: "Collections", description: "Runs the ITEM path once for each item, then DONE once.", outputs: ["item", "done"], config_fields: [{ key: "collection", type: "template" }, { key: "execution_mode", type: "select", options: ["sequential", "parallel"] }, { key: "parallelism", type: "number" }, { key: "failure_policy", type: "select", options: ["stop_all", "continue", "collect_errors"] }, { key: "max_items", type: "number" }] },
        { key: "random_split", display_name: "Random Split", category: "Logic", description: "Chooses one weighted path and persists the choice.", outputs: ["path_a", "path_b"], dynamic_ports: true, config_fields: [{ key: "mode", type: "select", options: ["per_run", "sticky_subject"] }, { key: "paths", type: "weighted_ports" }] },
        { key: "event_wait_multi", display_name: "Wait for Any Event", category: "Wait & Events", description: "Waits for the first matching event from several subscriptions.", outputs: ["timeout"], dynamic_ports: true, config_fields: [{ key: "events", type: "event_list" }, { key: "timeout", type: "duration" }] },
        { key: "wait", display_name: "Wait", category: "Timing", description: "Persists a duration, date, business-day, random, or event wait.", outputs: ["default", "event", "timeout"], config_fields: [{ key: "mode", type: "select", options: ["duration", "until_datetime", "event_wait", "business_days", "next_business_open", "random_duration"] }] },
        { key: "variable.set", display_name: "Set Variable", category: "Utility", description: "Stores a run variable.", outputs: ["default"], config_fields: [{ key: "name", type: "text" }, { key: "value", type: "template" }] },
        { key: "goal", display_name: "Goal Reached", category: "Flow Control", description: "Records a workflow goal and continues.", outputs: ["default"], config_fields: [{ key: "goal_key", type: "text" }, { key: "metadata", type: "json" }] },
        { key: "stop", display_name: "Stop Automation", category: "Flow Control", description: "Stops the entire run.", outputs: [], config_fields: [{ key: "reason", type: "text" }] },
        { key: "end", display_name: "End Path", category: "Flow Control", description: "Ends only the current path.", outputs: [], config_fields: [{ key: "reason", type: "text" }] },
        { key: "fail", display_name: "Fail Automation", category: "Flow Control", description: "Fails the run with a configured reason.", outputs: [], config_fields: [{ key: "reason", type: "text" }] },
        { key: "automation.start", display_name: "Start Automation", category: "Utility", description: "Starts another published automation.", outputs: ["default"], config_fields: [{ key: "automation_id", type: "automation" }] },
        { key: "note", display_name: "Note", category: "Notes", description: "Editor-only annotation. Does not execute.", outputs: [], config_fields: [{ key: "title", type: "text" }, { key: "body", type: "multiline" }] }
      ]
    });
  });

  app.get("/api/automations/settings", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `SELECT automations_enabled,
                automation_emergency_stopped_at,
                automation_max_active_runs,
                automation_run_starts_per_minute,
                automation_node_executions_per_minute,
                automated_customer_messages_enabled,
                automation_sms_default_business_hours_policy,
                automation_sms_max_per_contact_hour,
                automation_sms_max_per_contact_day
           FROM companies
          WHERE id = $1`,
        [req.companyId]
      );
      res.json(rows[0] || {});
    } catch (e) {
      console.error("[automations] settings failed", e?.message || e);
      res.status(500).json({ error: "automation_settings_failed" });
    }
  });

  app.put("/api/automations/settings", authRequired, requireEmployer, async (req, res) => {
    try {
      const automationsEnabled = req.body?.automations_enabled !== false;
      const enabled = req.body?.automated_customer_messages_enabled !== false;
      const policy = ["send_immediately", "defer_until_business_hours", "skip_if_outside_business_hours"].includes(req.body?.automation_sms_default_business_hours_policy)
        ? req.body.automation_sms_default_business_hours_policy
        : "send_immediately";
      const hourMax = Math.max(0, Math.min(200, Number(req.body?.automation_sms_max_per_contact_hour ?? 6) || 0));
      const dayMax = Math.max(0, Math.min(1000, Number(req.body?.automation_sms_max_per_contact_day ?? 20) || 0));
      const maxActiveRuns = Math.max(1, Math.min(1000, Number(req.body?.automation_max_active_runs ?? AUTOMATION_SAFETY_DEFAULTS.maxCompanyActiveRuns) || AUTOMATION_SAFETY_DEFAULTS.maxCompanyActiveRuns));
      const startsPerMinute = Math.max(1, Math.min(5000, Number(req.body?.automation_run_starts_per_minute ?? AUTOMATION_SAFETY_DEFAULTS.runStartsPerMinute) || AUTOMATION_SAFETY_DEFAULTS.runStartsPerMinute));
      const nodesPerMinute = Math.max(1, Math.min(50000, Number(req.body?.automation_node_executions_per_minute ?? AUTOMATION_SAFETY_DEFAULTS.nodeExecutionsPerMinute) || AUTOMATION_SAFETY_DEFAULTS.nodeExecutionsPerMinute));
      const { rows } = await ctx.pool.query(
        `UPDATE companies
            SET automations_enabled = $2,
                automated_customer_messages_enabled = $3,
                automation_sms_default_business_hours_policy = $4,
                automation_sms_max_per_contact_hour = $5,
                automation_sms_max_per_contact_day = $6,
                automation_max_active_runs = $7,
                automation_run_starts_per_minute = $8,
                automation_node_executions_per_minute = $9,
                automation_emergency_stopped_at = CASE WHEN $2 THEN NULL ELSE automation_emergency_stopped_at END
          WHERE id = $1
          RETURNING automations_enabled,
                    automation_emergency_stopped_at,
                    automation_max_active_runs,
                    automation_run_starts_per_minute,
                    automation_node_executions_per_minute,
                    automated_customer_messages_enabled,
                    automation_sms_default_business_hours_policy,
                    automation_sms_max_per_contact_hour,
                    automation_sms_max_per_contact_day`,
        [req.companyId, automationsEnabled, enabled, policy, hourMax, dayMax, maxActiveRuns, startsPerMinute, nodesPerMinute]
      );
      res.json(rows[0] || {});
    } catch (e) {
      console.error("[automations] settings update failed", e?.message || e);
      res.status(500).json({ error: "automation_settings_update_failed" });
    }
  });

  app.post("/api/automations/pause-all", authRequired, requireEmployer, async (req, res) => {
    try {
      await ctx.pool.query(`UPDATE companies SET automations_enabled = false, updated_at = now() WHERE id = $1`, [req.companyId]);
      await ctx.pool.query(`UPDATE automation_definitions SET status = 'paused', updated_at = now() WHERE company_id = $1 AND status = 'published'`, [req.companyId]);
      res.json({ ok: true });
    } catch (e) {
      console.error("[automations] pause all failed", e?.message || e);
      res.status(500).json({ error: "automation_pause_all_failed" });
    }
  });

  app.post("/api/automations/resume-all", authRequired, requireEmployer, async (req, res) => {
    try {
      await ctx.pool.query(`UPDATE companies SET automations_enabled = true, automation_emergency_stopped_at = NULL, updated_at = now() WHERE id = $1`, [req.companyId]);
      await ctx.pool.query(`UPDATE automation_definitions SET status = 'published', pause_until = NULL, updated_at = now() WHERE company_id = $1 AND status = 'paused'`, [req.companyId]);
      res.json({ ok: true });
    } catch (e) {
      console.error("[automations] resume all failed", e?.message || e);
      res.status(500).json({ error: "automation_resume_all_failed" });
    }
  });

  app.post("/api/automations/emergency-stop", authRequired, requireEmployer, async (req, res) => {
    if (req.body?.confirm !== true) return res.status(400).json({ error: "confirmation_required" });
    try {
      const result = await emergencyStopCompanyAutomations(req.companyId, req.userId);
      res.json(result);
    } catch (e) {
      console.error("[automations] emergency stop failed", e?.message || e);
      res.status(500).json({ error: "automation_emergency_stop_failed" });
    }
  });

  app.get("/api/automations", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `SELECT d.id, d.name, d.description, d.status, d.folder_id, f.name AS folder_name,
                d.active_version_id, av.version_number AS published_version_number, d.pause_until,
                d.allow_manual_trigger, d.created_at, d.updated_at,
                (SELECT COUNT(*)::int FROM automation_runs r WHERE r.automation_id = d.id AND r.created_at > now() - interval '7 days') AS recent_run_count,
                (SELECT r.status FROM automation_runs r WHERE r.automation_id = d.id ORDER BY r.created_at DESC LIMIT 1) AS last_run_status,
                (SELECT r.created_at FROM automation_runs r WHERE r.automation_id = d.id ORDER BY r.created_at DESC LIMIT 1) AS last_triggered_at
           FROM automation_definitions d
           LEFT JOIN automation_folders f ON f.id = d.folder_id
           LEFT JOIN automation_versions av ON av.id = d.active_version_id
          WHERE d.company_id = $1 AND d.status <> 'archived'
          ORDER BY d.updated_at DESC`,
        [req.companyId]
      );
      res.json(rows);
    } catch (e) {
      console.error("[automations] list failed", e?.message || e);
      res.status(500).json({ error: "automation_list_failed" });
    }
  });

  app.post("/api/automations", authRequired, requireEmployer, async (req, res) => {
    const name = (req.body?.name || "").toString().trim();
    if (!name) return res.status(400).json({ error: "name_required" });
    const db = await ctx.pool.connect();
    try {
      await db.query("BEGIN");
      const definition = await db.query(
        `INSERT INTO automation_definitions(company_id, folder_id, name, description, created_by_user_id, updated_by_user_id, metadata)
         VALUES($1,$2,$3,$4,$5,$5,$6::jsonb) RETURNING *`,
        [req.companyId, req.body?.folder_id || null, name, req.body?.description || null, req.userId, JSON.stringify({ reentry_mode: "after_previous_completion" })]
      );
      const version = await db.query(
        `INSERT INTO automation_versions(automation_id, company_id, version_number, status, created_by_user_id)
         VALUES($1,$2,1,'draft',$3) RETURNING *`,
        [definition.rows[0].id, req.companyId, req.userId]
      );
      await db.query(`UPDATE automation_definitions SET draft_version_id = $2 WHERE id = $1`, [definition.rows[0].id, version.rows[0].id]);
      await db.query("COMMIT");
      res.status(201).json({ ...definition.rows[0], draft_version_id: version.rows[0].id, draft_version: version.rows[0] });
    } catch (e) {
      await db.query("ROLLBACK").catch(() => {});
      console.error("[automations] create failed", e?.message || e);
      res.status(500).json({ error: "automation_create_failed" });
    } finally {
      db.release();
    }
  });

  app.get("/api/automations/health", authRequired, requireEmployer, async (req, res) => {
    try {
      res.json(await automationHealth(req.companyId));
    } catch (e) {
      res.status(500).json({ error: "automation_health_failed" });
    }
  });

  app.get("/api/automations/system-issues", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `SELECT * FROM automation_dead_letters WHERE company_id = $1 AND status = COALESCE($2, status) ORDER BY failed_at DESC LIMIT 100`,
        [req.companyId, req.query?.status || "open"]
      );
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: "automation_issues_failed" });
    }
  });

  app.post("/api/automations/system-issues/:id/dismiss", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `UPDATE automation_dead_letters SET status = 'dismissed', dismissed_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "not_found" });
      res.json(rows[0]);
    } catch (e) {
      res.status(500).json({ error: "automation_issue_dismiss_failed" });
    }
  });

  app.post("/api/automations/system-issues/:id/retry", authRequired, requireEmployer, async (req, res) => {
    try {
      const result = await retryDeadLetter(req.params.id, req.companyId, req.userId);
      if (!result) return res.status(404).json({ error: "not_found" });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: "automation_issue_retry_failed" });
    }
  });

  app.get("/api/automations/:id", authRequired, requireEmployer, async (req, res) => {
    try {
      const detail = await loadAutomationDetail(req.params.id, req.companyId);
      if (!detail) return res.status(404).json({ error: "not_found" });
      res.json(detail);
    } catch (e) {
      res.status(500).json({ error: "automation_get_failed" });
    }
  });

  app.patch("/api/automations/:id", authRequired, requireEmployer, async (req, res) => {
    const allowed = ["name", "description", "folder_id", "allow_manual_trigger", "max_parallel_runs_per_subject", "max_active_runs", "max_active_runs_per_subject", "concurrency_policy", "subject_concurrency_policy", "reentry_mode", "cooldown_seconds", "cooldown_basis", "failure_auto_pause_enabled", "failure_auto_pause_threshold", "failure_auto_pause_window_seconds", "metadata"];
    const sets = [];
    const values = [req.params.id, req.companyId, req.userId];
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) {
        values.push(key === "metadata" ? JSON.stringify(req.body[key] || {}) : req.body[key]);
        sets.push(`${key} = $${values.length}${key === "metadata" ? "::jsonb" : ""}`);
      }
    }
    if (!sets.length) return res.status(400).json({ error: "no_changes" });
    try {
      const { rows } = await ctx.pool.query(
        `UPDATE automation_definitions SET ${sets.join(", ")}, updated_by_user_id = $3, updated_at = now()
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        values
      );
      if (!rows.length) return res.status(404).json({ error: "not_found" });
      res.json(rows[0]);
    } catch (e) {
      res.status(500).json({ error: "automation_update_failed" });
    }
  });

  app.delete("/api/automations/:id", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `UPDATE automation_definitions SET status = 'archived', updated_by_user_id = $3, updated_at = now()
          WHERE id = $1 AND company_id = $2 RETURNING id`,
        [req.params.id, req.companyId, req.userId]
      );
      if (!rows.length) return res.status(404).json({ error: "not_found" });
      res.status(204).end();
    } catch (e) {
      res.status(500).json({ error: "automation_archive_failed" });
    }
  });

  app.post("/api/automations/:id/duplicate", authRequired, requireEmployer, async (req, res) => {
    try {
      const copy = await duplicateAutomation(req.params.id, req.companyId, req.userId);
      if (!copy) return res.status(404).json({ error: "not_found" });
      res.status(201).json(copy);
    } catch (e) {
      console.error("[automations] duplicate failed", e?.message || e);
      res.status(500).json({ error: "automation_duplicate_failed" });
    }
  });

  app.post("/api/automations/:id/pause", authRequired, requireEmployer, async (req, res) => {
    try {
      const pauseUntil = req.body?.pause_until || null;
      const { rows } = await ctx.pool.query(
        `UPDATE automation_definitions SET status = 'paused', pause_until = $3::timestamptz, updated_by_user_id = $4, updated_at = now()
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        [req.params.id, req.companyId, pauseUntil, req.userId]
      );
      if (!rows.length) return res.status(404).json({ error: "not_found" });
      res.json(rows[0]);
    } catch (e) {
      res.status(500).json({ error: "automation_pause_failed" });
    }
  });

  app.post("/api/automations/:id/resume", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `UPDATE automation_definitions SET status = CASE WHEN active_version_id IS NULL THEN 'draft' ELSE 'published' END,
             pause_until = NULL, updated_by_user_id = $3, updated_at = now()
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        [req.params.id, req.companyId, req.userId]
      );
      if (!rows.length) return res.status(404).json({ error: "not_found" });
      res.json(rows[0]);
    } catch (e) {
      res.status(500).json({ error: "automation_resume_failed" });
    }
  });

  app.get("/api/automations/:id/draft", authRequired, requireEmployer, async (req, res) => {
    try {
      const draft = await ensureDraftVersion(req.params.id, req.companyId, req.userId);
      if (!draft) return res.status(404).json({ error: "not_found" });
      res.json(await loadVersionGraph(draft.id, req.companyId));
    } catch (e) {
      console.error("[automations] draft failed", e?.message || e);
      res.status(500).json({ error: "automation_draft_failed" });
    }
  });

  app.put("/api/automations/:id/draft/graph", authRequired, requireEmployer, async (req, res) => {
    try {
      const draft = await ensureDraftVersion(req.params.id, req.companyId, req.userId);
      if (!draft) return res.status(404).json({ error: "not_found" });
      const validation = validateGraphPayload(req.body || {});
      if (!validation.valid) return res.status(400).json(validation);
      await saveDraftGraph(draft.id, req.companyId, req.body || {});
      res.json(await loadVersionGraph(draft.id, req.companyId));
    } catch (e) {
      console.error("[automations] save graph failed", e?.message || e);
      res.status(500).json({ error: "automation_graph_save_failed" });
    }
  });

  app.post("/api/automations/:id/publish", authRequired, requireEmployer, async (req, res) => {
    try {
      const result = await publishAutomation(req.params.id, req.companyId, req.userId);
      if (!result) return res.status(404).json({ error: "not_found" });
      if (!result.valid) return res.status(400).json(result);
      res.json(result);
    } catch (e) {
      console.error("[automations] publish failed", e?.message || e);
      res.status(500).json(safeAutomationErrorResponse(e, "automation_publish_failed", "WolfCRM couldn't create the published automation version."));
    }
  });

  app.post("/api/automations/validate-graph", authRequired, requireEmployer, async (req, res) => {
    res.json(validateGraphPayload(req.body || {}));
  });

  app.post("/api/automations/:id/draft/test", authRequired, requireEmployer, async (req, res) => {
    try {
      const run = await startDraftTestRun(req.params.id, req.companyId, req.userId, req.body || {});
      if (!run) return res.status(404).json({ error: "not_found" });
      res.status(202).json(run);
    } catch (e) {
      console.error("[automations] draft test failed", e?.message || e);
      res.status(500).json(safeAutomationErrorResponse(e, "automation_draft_test_failed", "WolfCRM couldn't start the draft test run."));
    }
  });

  app.post("/api/automations/:id/manual-run", authRequired, requireEmployer, async (req, res) => {
    try {
      const run = await startManualRun(req.params.id, req.companyId, req.userId, req.body || {});
      if (!run) return res.status(404).json({ error: "not_found" });
      res.status(202).json(run);
    } catch (e) {
      console.error("[automations] manual run failed", e?.message || e);
      res.status(500).json({ error: "automation_manual_run_failed" });
    }
  });

  app.get("/api/automations/:id/runs", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `SELECT id, automation_id, automation_version_id, trigger_event_id, subject_type, subject_id, status,
                started_at, completed_at, current_node_count, error_code, error_message, dry_run, created_at, updated_at
           FROM automation_runs
          WHERE company_id = $1 AND automation_id = $2
          ORDER BY created_at DESC LIMIT 100`,
        [req.companyId, req.params.id]
      );
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: "automation_runs_failed" });
    }
  });

  app.get("/api/automation-runs/:runId", authRequired, requireEmployer, async (req, res) => {
    try {
      const detail = await loadRunDetail(req.params.runId, req.companyId);
      if (!detail) return res.status(404).json({ error: "not_found" });
      res.json(detail);
    } catch (e) {
      res.status(500).json({ error: "automation_run_failed" });
    }
  });

  app.post("/api/automation-runs/:runId/cancel", authRequired, requireEmployer, async (req, res) => {
    try {
      const result = await cancelAutomationRun(req.params.runId, req.companyId, "run_canceled", "Run canceled by employer", { user_id: req.userId });
      if (!result.run) return res.status(404).json({ error: "not_found" });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: "automation_cancel_failed" });
    }
  });

  app.post("/api/automation-runs/:runId/retry", authRequired, requireEmployer, async (req, res) => {
    try {
      const result = await retryAutomationRun(req.params.runId, req.companyId, req.userId);
      if (!result) return res.status(404).json({ error: "not_found" });
      res.status(202).json(result);
    } catch (e) {
      res.status(500).json({ error: "automation_retry_failed" });
    }
  });

  app.post("/api/automation-runs/:runId/nodes/:runNodeId/retry", authRequired, requireEmployer, async (req, res) => {
    try {
      const result = await retryAutomationRunNode(req.params.runId, req.params.runNodeId, req.companyId, req.userId);
      if (!result) return res.status(404).json({ error: "not_found" });
      res.status(202).json(result);
    } catch (e) {
      res.status(500).json({ error: "automation_node_retry_failed" });
    }
  });

  app.post("/api/automation-runs/:runId/iterations/:iterationId/retry", authRequired, requireEmployer, async (req, res) => {
    try {
      const result = await retryAutomationIteration(req.params.runId, req.params.iterationId, req.companyId, req.userId);
      if (!result) return res.status(404).json({ error: "not_found" });
      res.status(202).json(result);
    } catch (e) {
      res.status(500).json({ error: "automation_iteration_retry_failed" });
    }
  });
}

async function loadAutomationDetail(id, companyId) {
  const { rows } = await ctx.pool.query(`SELECT * FROM automation_definitions WHERE id = $1 AND company_id = $2`, [id, companyId]);
  if (!rows.length) return null;
  const draft = rows[0].draft_version_id ? await loadVersionGraph(rows[0].draft_version_id, companyId) : null;
  const active = rows[0].active_version_id ? await loadVersionGraph(rows[0].active_version_id, companyId) : null;
  return { ...rows[0], draft, active };
}

async function loadVersionGraph(versionId, companyId) {
  const version = (await ctx.pool.query(`SELECT * FROM automation_versions WHERE id = $1 AND company_id = $2`, [versionId, companyId])).rows[0];
  if (!version) return null;
  const nodes = (await ctx.pool.query(`SELECT * FROM automation_nodes WHERE version_id = $1 AND company_id = $2 ORDER BY created_at ASC`, [versionId, companyId])).rows;
  const edges = (await ctx.pool.query(`SELECT * FROM automation_edges WHERE version_id = $1 AND company_id = $2 ORDER BY priority ASC, created_at ASC`, [versionId, companyId])).rows;
  return { version, nodes, edges, settings: version.settings || {} };
}

async function ensureDraftVersion(automationId, companyId, userId) {
  const definition = (await ctx.pool.query(`SELECT * FROM automation_definitions WHERE id = $1 AND company_id = $2`, [automationId, companyId])).rows[0];
  if (!definition) return null;
  if (definition.draft_version_id) {
    const existing = (await ctx.pool.query(`SELECT * FROM automation_versions WHERE id = $1 AND status = 'draft'`, [definition.draft_version_id])).rows[0];
    if (existing) return existing;
  }
  const sourceVersionId = definition.active_version_id;
  const db = await ctx.pool.connect();
  try {
    await db.query("BEGIN");
    const maxRow = (await db.query(`SELECT COALESCE(MAX(version_number),0)::int AS n FROM automation_versions WHERE automation_id = $1`, [automationId])).rows[0];
    const draft = (await db.query(
      `INSERT INTO automation_versions(automation_id, company_id, version_number, status, created_by_user_id, settings)
       VALUES($1,$2,$3,'draft',$4,COALESCE((SELECT settings FROM automation_versions WHERE id = $5),'{}'::jsonb)) RETURNING *`,
      [automationId, companyId, maxRow.n + 1, userId, sourceVersionId]
    )).rows[0];
    if (sourceVersionId) await copyGraph(db, sourceVersionId, draft.id, companyId);
    await db.query(`UPDATE automation_definitions SET draft_version_id = $2, updated_by_user_id = $3, updated_at = now() WHERE id = $1`, [automationId, draft.id, userId]);
    await db.query("COMMIT");
    return draft;
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    db.release();
  }
}

function validateGraphPayload(payload) {
  const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
  const edges = Array.isArray(payload.edges) ? payload.edges : [];
  const errors = [];
  const warnings = [];
  const nodeIds = new Set();
  const nodeKeys = new Set();
  const validTypes = new Set(["trigger", "action", "condition", "wait", "branch", "sub_automation", "utility", "note", "foreach", "merge", "parallel", "switch", "random_split", "event_wait_multi", "goal", "stop", "end", "fail"]);
  const settings = payload.settings || {};
  validateAutomationSafetySettings(settings, errors, warnings);
  const hasContactContext = graphProvidesContactContext(nodes);
  const contextTypes = graphProvidedContextTypes(nodes);
  for (const node of nodes) {
    if (!node.id) errors.push("node_missing_id");
    if (!node.node_key && !node.nodeKey) errors.push("node_missing_key");
    if (nodeIds.has(node.id)) errors.push(`duplicate_node_id:${node.id}`);
    nodeIds.add(node.id);
    const nodeKey = node.node_key || node.nodeKey;
    if (nodeKeys.has(nodeKey)) errors.push(`duplicate_node_key:${nodeKey}`);
    nodeKeys.add(nodeKey);
    if (!validTypes.has(node.node_type || node.nodeType)) errors.push(`invalid_node_type:${nodeKey}`);
    const nodeType = node.node_type || node.nodeType;
    const config = node.config || {};
    validateNodeSafetyConfig(nodeKey, nodeType, config, errors, warnings);
    if (nodeType === "trigger" && !triggerCatalog.find((t) => t.key === config.trigger_key)) errors.push(`invalid_trigger:${nodeKey}`);
    if (nodeType === "action" && !actionExecutors[config.action_key]) errors.push(`invalid_action:${nodeKey}`);
    if (nodeType === "trigger" && config.trigger_key === "contact.field_changed" && !config.field) errors.push(`field_change_trigger_missing_field:${nodeKey}`);
    if (nodeType === "action") {
      if (["contact.add_tag", "contact.remove_tag", "contact.replace_tags"].includes(config.action_key) && !normalizeTags(config.tags || config.tag).length) errors.push(`tags_required:${nodeKey}`);
      if (config.action_key === "contact.delete" && config.confirm_delete !== true) errors.push(`delete_confirmation_required:${nodeKey}`);
      if (["pipeline.create_opportunity", "pipeline.move_stage", "pipeline.reopen"].includes(config.action_key) && !config.stage_id) errors.push(`stage_required:${nodeKey}`);
      if (config.action_key === "pipeline.set_value" && config.value == null && config.value_cents == null) errors.push(`value_required:${nodeKey}`);
      if (config.action_key === "contact.set_custom_field" && !["u1", "u2", "u3", "u4", "u5"].includes(config.field)) errors.push(`custom_field_required:${nodeKey}`);
      if (config.action_key === "job.create" && (!config.title || !config.start_at)) errors.push(`job_create_missing_title_or_start:${nodeKey}`);
      if (config.action_key === "job.reschedule" && !config.start_at) errors.push(`job_reschedule_missing_start:${nodeKey}`);
      if (config.action_key === "job.delete" && config.confirm_delete !== true) errors.push(`job_delete_confirmation_required:${nodeKey}`);
      if (["job.assign_worker", "job.remove_worker", "job.assign_salesperson", "job.remove_salesperson"].includes(config.action_key) && !config.user_id) errors.push(`job_user_required:${nodeKey}`);
      if (["job.add_service", "job.remove_service"].includes(config.action_key) && !(config.service || config.name)) errors.push(`job_service_required:${nodeKey}`);
      if (config.action_key === "schedule.find_available_slots" && Number(config.duration_minutes || 0) <= 0) errors.push(`availability_duration_required:${nodeKey}`);
      if (config.action_key === "task.create" && !config.title) errors.push(`task_title_required:${nodeKey}`);
      if (config.action_key === "task.reschedule" && !config.due_date) errors.push(`task_due_required:${nodeKey}`);
      if (config.action_key === "routine.create" && !config.title) errors.push(`routine_title_required:${nodeKey}`);
      if (config.action_key === "customer_reminder.create" && !config.due_date) errors.push(`customer_reminder_due_required:${nodeKey}`);
      if (["sms.send", "call.send_followup_sms", "voicemail.send_followup_sms"].includes(config.action_key) && !config.body) errors.push(`sms_body_required:${nodeKey}`);
      if (config.action_key === "sms.send_mms" && !config.body && !(Array.isArray(config.media) && config.media.length)) errors.push(`mms_body_or_media_required:${nodeKey}`);
      if (["sms.send", "sms.send_mms", "call.send_followup_sms", "voicemail.send_followup_sms"].includes(config.action_key)) {
        const targetMode = config.target_mode || (config.phone ? "phone_number" : "current_contact");
        if (targetMode === "phone_number" && !config.phone) errors.push(`sms_phone_required:${nodeKey}`);
        if (targetMode === "phone_template" && !config.phone) errors.push(`sms_phone_variable_required:${nodeKey}`);
        if (isBracedNumericLiteral(config.phone)) errors.push(`sms_phone_number_wrapped_as_template:${nodeKey}`);
      }
      if (["sms.delete_local_message"].includes(config.action_key) && !config.message_id) warnings.push(`message_id_defaults_to_context:${nodeKey}`);
      if (["sms.mark_conversation_read", "sms.mark_conversation_unread", "sms.delete_local_conversation"].includes(config.action_key) && !config.conversation_id) warnings.push(`conversation_id_defaults_to_context:${nodeKey}`);
      if (config.action_key === "internal.send_dm" && !config.recipient_user_id) errors.push(`internal_recipient_required:${nodeKey}`);
      if (config.action_key === "internal.send_channel_message" && !config.channel_id) errors.push(`internal_channel_required:${nodeKey}`);
      if (config.action_key === "internal.create_channel" && !config.name) errors.push(`internal_channel_name_required:${nodeKey}`);
      if (["call.set_disposition"].includes(config.action_key) && !config.disposition) errors.push(`call_disposition_required:${nodeKey}`);
      if (config.action_key === "contact.create" && !config.name) errors.push(`contact_name_required:${nodeKey}`);
      if (actionRequiresContactTarget(config.action_key) && (config.target_mode || "current_contact") === "current_contact" && !hasContactContext) errors.push(`target_contact_required:${nodeKey}`);
      validateResourceTarget(config, nodeKey, contextTypes, errors);
      if (config.action_key === "quote.create" && !(Array.isArray(config.line_items) && config.line_items.length)) errors.push(`quote_line_items_required:${nodeKey}`);
      if (config.action_key === "quote.delete" && config.confirm_delete !== true) errors.push(`quote_delete_confirmation_required:${nodeKey}`);
      if (config.action_key === "quote.set_status" && !["draft", "sent", "accepted", "declined", "expired", "converted"].includes(config.status)) errors.push(`quote_status_invalid:${nodeKey}`);
      if (config.action_key === "quote.set_expiration" && !config.expires_at) errors.push(`quote_expiration_required:${nodeKey}`);
      if (["invoice.create", "payment.create_request", "payment.create_payment_link", "invoice.create_payment_request", "payment.record_manual_payment"].includes(config.action_key) && Number(config.amount_cents || config.total_cents || 0) <= 0 && !config.line_items) errors.push(`financial_amount_required:${nodeKey}`);
      if (config.action_key === "invoice.void" && config.confirm_void !== true) errors.push(`invoice_void_confirmation_required:${nodeKey}`);
      if (config.action_key === "service_plan.create" && (!config.plan_name || Number(config.price_cents || 0) <= 0)) errors.push(`service_plan_create_incomplete:${nodeKey}`);
      if (config.action_key === "service_plan.cancel" && config.confirm_cancel !== true) errors.push(`service_plan_cancel_confirmation_required:${nodeKey}`);
      if (["service_plan.set_service_interval", "service_plan.set_billing_interval"].includes(config.action_key) && !(config.service_interval || config.billing_interval)) errors.push(`service_plan_interval_required:${nodeKey}`);
      if (config.action_key === "service_plan.set_next_service_date" && !config.next_service_date) errors.push(`service_plan_next_service_required:${nodeKey}`);
      if (config.action_key === "map.create_pin" && (config.latitude == null || config.longitude == null) && !config.address) errors.push(`map_pin_location_required:${nodeKey}`);
      if (config.action_key === "map.delete_pin" && config.confirm_delete !== true) errors.push(`map_delete_confirmation_required:${nodeKey}`);
      if (config.action_key === "map.set_status" && !mapStatusOptions().includes(String(config.status || ""))) errors.push(`invalid_map_status:${nodeKey}`);
      if (config.action_key === "map.schedule_followup" && Number(config.amount || 0) <= 0) errors.push(`map_followup_amount_required:${nodeKey}`);
      if (config.action_key === "route.delete" && config.confirm_delete !== true) errors.push(`route_delete_confirmation_required:${nodeKey}`);
      if (["route.add_stop", "route.add_contact", "route.add_pin", "route.add_job"].includes(config.action_key) && !config.route_id) warnings.push(`route_context_required_at_runtime:${nodeKey}`);
      if (config.action_key === "route.add_job" && !config.job_id && config.target_mode !== "current_job") warnings.push(`route_job_context_required_at_runtime:${nodeKey}`);
      if (config.action_key === "employee.update_role" && config.confirm_sensitive_change !== true) errors.push(`employee_role_confirmation_required:${nodeKey}`);
      if (config.action_key === "employee.deactivate" && config.confirm_deactivate !== true) errors.push(`employee_deactivate_confirmation_required:${nodeKey}`);
      if (config.action_key === "time_clock.flag_for_review" && !config.review_reason) warnings.push(`time_review_reason_recommended:${nodeKey}`);
      if (config.action_key === "measurement.create_record" && (!Array.isArray(config.points) || config.points.length < 2)) warnings.push(`measurement_points_recommended:${nodeKey}`);
      if (config.action_key?.startsWith("collection.") && !config.collection && config.action_key !== "collection.concat") errors.push(`collection_input_required:${nodeKey}`);
      if (config.action_key === "collection.limit" && Number(config.limit || 0) <= 0) errors.push(`collection_limit_required:${nodeKey}`);
      if (config.action_key === "math" && config.operation === "divide" && Number(config.b || 0) === 0) warnings.push(`math_divide_by_zero_if_literal:${nodeKey}`);
      if (config.action_key === "object.get" && !isSafeObjectPath(config.path || "")) errors.push(`unsafe_object_path:${nodeKey}`);
    }
    if (nodeType === "foreach") {
      if (!config.collection) errors.push(`foreach_collection_required:${nodeKey}`);
      if (Number(config.max_items || 1) <= 0) errors.push(`foreach_max_items_required:${nodeKey}`);
      if (Number(config.max_items || 1) > AUTOMATION_LIMITS.foreachHardMaxItems) errors.push(`foreach_max_items_too_large:${nodeKey}`);
      if (config.execution_mode === "parallel" && (Number(config.parallelism || 0) <= 0 || Number(config.parallelism || 0) > AUTOMATION_LIMITS.foreachMaxParallelism)) errors.push(`foreach_parallelism_invalid:${nodeKey}`);
    }
    if (nodeType === "merge") {
      const incomingCount = edges.filter((edge) => (edge.target_node_id || edge.targetNodeId) === node.id).length;
      if (!incomingCount) errors.push(`merge_incoming_required:${nodeKey}`);
      if ((config.mode || "any") === "all" && incomingCount === 1) warnings.push(`merge_all_single_incoming:${nodeKey}`);
    }
    if (nodeType === "random_split") {
      const paths = normalizeDynamicPorts(config, []);
      const total = paths.reduce((sum, path) => sum + Number(path.weight || 0), 0);
      if (paths.length < 2) errors.push(`random_split_two_paths_required:${nodeKey}`);
      if (Math.round(total) !== 100) errors.push(`random_split_weights_must_total_100:${nodeKey}`);
      if (new Set(paths.map((path) => path.id)).size !== paths.length) errors.push(`random_split_duplicate_ports:${nodeKey}`);
    }
    if (nodeType === "event_wait_multi") {
      if (!Array.isArray(config.events) || !config.events.length) errors.push(`multi_wait_events_required:${nodeKey}`);
      if (config.timeout && parseDurationMs(config.timeout) <= 0) errors.push(`multi_wait_timeout_invalid:${nodeKey}`);
    }
    if (nodeType === "trigger" && config.trigger_key === "job.relative_time" && (!config.reference || !config.direction || !config.amount || !config.unit)) errors.push(`relative_time_trigger_incomplete:${nodeKey}`);
    if (nodeType === "trigger" && ["sms.no_reply", "sms.conversation_inactive", "voicemail.unread_for"].includes(config.trigger_key) && Number(config.amount || 0) <= 0) errors.push(`communication_duration_required:${nodeKey}`);
    if (nodeType === "trigger" && config.trigger_key === "sms.keyword_received" && !(Array.isArray(config.keywords) && config.keywords.length)) errors.push(`sms_keywords_required:${nodeKey}`);
    if (nodeType === "trigger" && ["call.short_call", "call.long_call"].includes(config.trigger_key) && Number(config.threshold_seconds || 0) <= 0) errors.push(`call_duration_threshold_required:${nodeKey}`);
    if (nodeType === "trigger" && config.trigger_key === "quote.followup_due" && Number(config.amount || 0) <= 0) errors.push(`quote_followup_duration_required:${nodeKey}`);
    if (nodeType === "trigger" && ["service_plan.service_upcoming", "service_plan.service_overdue"].includes(config.trigger_key) && Number(config.amount || 0) <= 0) errors.push(`service_plan_offset_required:${nodeKey}`);
    if (nodeType === "trigger" && config.trigger_key === "map.pin_followup_due" && Number(config.amount || 0) <= 0) errors.push(`map_followup_duration_required:${nodeKey}`);
    if (nodeType === "trigger" && ["time_clock.shift_duration_reached", "time_clock.overtime_threshold_reached", "time_clock.missed_clock_out"].includes(config.trigger_key) && Number(config.amount || 0) <= 0) errors.push(`time_clock_threshold_required:${nodeKey}`);
  }
  for (const edge of edges) {
    if (!nodeIds.has(edge.source_node_id || edge.sourceNodeId)) errors.push(`edge_source_missing:${edge.id || ""}`);
    if (!nodeIds.has(edge.target_node_id || edge.targetNodeId)) errors.push(`edge_target_missing:${edge.id || ""}`);
  }
  for (const node of nodes) {
    const nodeKey = node.node_key || node.nodeKey;
    const config = node.config || {};
    if ((node.node_type || node.nodeType) === "action" && config.on_error === "error_path") {
      const hasErrorEdge = edges.some((edge) => (edge.source_node_id || edge.sourceNodeId) === node.id && (edge.source_port || edge.sourcePort) === "error");
      if (!hasErrorEdge) warnings.push(`error_path_unconnected:${nodeKey}`);
    }
  }
  if (!nodes.some((n) => (n.node_type || n.nodeType) === "trigger")) errors.push("trigger_required");
  detectObviousSelfTriggers(nodes, warnings);
  if (detectCycle(nodes, edges)) warnings.push("cycle_detected_execution_safety_limits_apply");
  return { valid: errors.length === 0, errors, warnings };
}

function graphProvidesContactContext(nodes) {
  return nodes.some((node) => {
    if ((node.node_type || node.nodeType) !== "trigger") return false;
    const key = node.config?.trigger_key || "";
    return key.startsWith("contact.") || key.startsWith("lead.") || key.startsWith("pipeline.") || key.startsWith("job.") || key.startsWith("sms.") || key.startsWith("call.") || key.startsWith("voicemail.") || key.startsWith("quote.") || key.startsWith("payment.") || key.startsWith("service_plan.");
  });
}

const ACTION_RESOURCE_TARGETS = {
  job: new Set(["job.update", "job.reschedule", "job.delete", "job.mark_completed", "job.reopen", "job.set_start", "job.set_end", "job.set_price", "job.set_material_cost", "job.set_color", "job.set_contact", "job.add_service", "job.remove_service", "job.assign_worker", "job.remove_worker", "job.replace_workers", "job.assign_salesperson", "job.remove_salesperson", "job.replace_salespeople", "job.add_note", "job.create_followup"]),
  task: new Set(["task.update", "task.complete", "task.reopen", "task.delete", "task.reschedule", "task.assign", "task.unassign", "task.add_subtask", "task.complete_subtask", "task.delete_subtask"]),
  quote: new Set(["quote.update", "quote.delete", "quote.add_line_item", "quote.remove_line_item", "quote.replace_line_items", "quote.set_status", "quote.mark_sent", "quote.mark_accepted", "quote.mark_declined", "quote.set_expiration", "quote.convert_to_job", "quote.create_followup_task"]),
  payment: new Set(["payment.send_payment_sms", "payment.send_payment_push", "payment.create_followup_task"]),
  service_plan: new Set(["service_plan.update", "service_plan.activate", "service_plan.pause", "service_plan.resume", "service_plan.cancel", "service_plan.mark_serviced", "service_plan.set_price", "service_plan.set_service_interval", "service_plan.set_billing_interval", "service_plan.set_next_service_date", "service_plan.create_next_job", "service_plan.create_service_task", "service_plan.send_scheduling_sms", "service_plan.create_payment_followup"]),
  map_pin: new Set(["map.update_pin", "map.delete_pin", "map.set_status", "map.add_to_list", "map.remove_from_list", "map.move_to_list", "map.link_contact", "map.unlink_contact", "map.create_contact", "map.add_note", "map.mark_visited", "map.record_knock", "map.schedule_followup"]),
  employee: new Set(["employee.update_role", "employee.deactivate", "employee.reactivate", "employee.send_push", "employee.send_internal_message", "employee.create_task"])
};

function graphProvidedContextTypes(nodes) {
  const types = new Set();
  for (const node of nodes) {
    const nodeType = node.node_type || node.nodeType;
    if (nodeType === "trigger") {
      const key = node.config?.trigger_key || "";
      if (key === "manual") types.add("generic");
      if (key.startsWith("contact.") || key.startsWith("lead.")) types.add("contact");
      if (key.startsWith("pipeline.")) { types.add("opportunity"); types.add("contact"); }
      if (key.startsWith("job.")) { types.add("job"); types.add("contact"); }
      if (key.startsWith("task.")) types.add("task");
      if (key.startsWith("quote.")) { types.add("quote"); types.add("contact"); }
      if (key.startsWith("payment.")) { types.add("payment"); types.add("contact"); }
      if (key.startsWith("service_plan.")) { types.add("service_plan"); types.add("contact"); }
      if (key.startsWith("map.") || key.startsWith("canvass.")) { types.add("map_pin"); types.add("contact"); }
      if (key.startsWith("employee.") || key.startsWith("time_clock.")) types.add("employee");
      if (key.startsWith("time_clock.")) types.add("time_entry");
    }
    if (nodeType === "action") {
      const action = node.config?.action_key || "";
      if (["contact.create", "map.create_contact", "phone.create_contact_from_number"].includes(action)) types.add("contact");
      if (["job.create", "job.create_followup", "quote.convert_to_job", "service_plan.create_next_job"].includes(action)) types.add("job");
      if (["task.create", "call.create_callback_task", "voicemail.create_callback_task", "payment.create_followup_task", "quote.create_followup_task", "service_plan.create_service_task", "employee.create_task", "time_clock.create_review_task"].includes(action)) types.add("task");
      if (action === "quote.create") types.add("quote");
      if (["payment.create_request", "payment.create_payment_link"].includes(action)) types.add("payment");
      if (action === "service_plan.create") types.add("service_plan");
      if (["map.create_pin", "contact.add_to_map"].includes(action)) types.add("map_pin");
    }
  }
  return types;
}

function validateResourceTarget(config, nodeKey, contextTypes, errors) {
  const specs = [
    ["job", "job_target_mode", "current_job", "job_id"],
    ["task", "task_target_mode", "current_task", "task_id"],
    ["quote", "quote_target_mode", "current_quote", "quote_id"],
    ["payment", "payment_target_mode", "current_payment", "payment_id"],
    ["service_plan", "service_plan_target_mode", "current_service_plan", "service_plan_id"],
    ["map_pin", "pin_target_mode", "current_pin", "pin_id"],
    ["employee", "employee_target_mode", "current_employee", "employee_id"]
  ];
  for (const [type, modeKey, currentMode, idKey] of specs) {
    if (!ACTION_RESOURCE_TARGETS[type]?.has(config.action_key)) continue;
    const mode = config[modeKey] || currentMode;
    if (config[idKey]) continue;
    if (mode === currentMode && !contextTypes.has(type)) errors.push(`${type}_target_required:${nodeKey}`);
    if (["specific", "node_output", "template"].includes(mode) && !config[idKey]) errors.push(`${type}_target_required:${nodeKey}`);
  }
}

function actionRequiresContactTarget(actionKey) {
  return [
    "contact.add_tag", "contact.remove_tag", "contact.replace_tags", "contact.clear_tags", "contact.update_fields",
    "contact.set_source", "contact.set_value", "contact.set_job_type", "contact.set_custom_field", "contact.set_location",
    "contact.delete", "contact.add_note", "contact.add_activity", "contact.add_to_map", "pipeline.create_opportunity",
    "pipeline.move_stage", "pipeline.set_value", "pipeline.mark_won", "pipeline.mark_lost", "pipeline.reopen",
    "pipeline.remove_opportunity", "pipeline.create_reminder", "sms.send", "sms.send_mms", "call.send_followup_sms",
    "voicemail.send_followup_sms"
  ].includes(actionKey);
}

function validateAutomationSafetySettings(settings, errors, warnings) {
  if (settings.reentry_mode === "cooldown" && Number(settings.cooldown_seconds || 0) <= 0) errors.push("cooldown_duration_required");
  for (const key of ["max_active_runs", "max_active_runs_per_subject", "maximum_node_executions", "max_customer_messages_per_run", "max_webhook_actions_per_run"]) {
    if (settings[key] != null && Number(settings[key]) <= 0) errors.push(`${key}_invalid`);
  }
  if (settings.max_active_runs != null && Number(settings.max_active_runs) > AUTOMATION_SAFETY_DEFAULTS.maxCompanyActiveRuns) errors.push("max_active_runs_over_system_limit");
  const stops = Array.isArray(settings.stop_conditions || settings.stopConditions) ? (settings.stop_conditions || settings.stopConditions) : [];
  for (const stop of stops) {
    const preset = stop?.key || stop?.preset || stop?.type;
    if (!preset && !stop?.event_type && !stop?.eventType) errors.push("stop_condition_event_required");
  }
  const goals = Array.isArray(settings.goals || settings.goal_conditions || settings.goalConditions) ? (settings.goals || settings.goal_conditions || settings.goalConditions) : [];
  for (const goal of goals) {
    if (!(goal?.key || goal?.name || goal?.event_type || goal?.eventType)) warnings.push("goal_condition_name_or_event_recommended");
  }
}

function validateNodeSafetyConfig(nodeKey, nodeType, config, errors, warnings) {
  const onError = config.on_error;
  if (onError && !["stop", "continue", "error_path"].includes(onError)) errors.push(`invalid_on_error:${nodeKey}`);
  const retryCount = Number(config.retry_count || 0);
  if (retryCount < 0 || retryCount > AUTOMATION_LIMITS.maxNodeAttempts - 1) errors.push(`retry_count_invalid:${nodeKey}`);
  if (config.retry_initial_delay_seconds != null && Number(config.retry_initial_delay_seconds) < 0) errors.push(`retry_initial_delay_invalid:${nodeKey}`);
  if (config.retry_max_delay_seconds != null && (Number(config.retry_max_delay_seconds) <= 0 || Number(config.retry_max_delay_seconds) > AUTOMATION_SAFETY_DEFAULTS.maxRetryDelaySeconds)) errors.push(`retry_max_delay_invalid:${nodeKey}`);
  if (config.retry_backoff_multiplier != null && Number(config.retry_backoff_multiplier) < 1) errors.push(`retry_backoff_invalid:${nodeKey}`);
  if (config.timeout_seconds != null && Number(config.timeout_seconds) <= 0) errors.push(`timeout_invalid:${nodeKey}`);
  if (config.missing_resource_policy && !["fail", "skip"].includes(config.missing_resource_policy)) errors.push(`missing_resource_policy_invalid:${nodeKey}`);
  if (nodeType === "sub_automation" && config.automation_id && config.automation_id === config.current_automation_id) errors.push(`self_start_not_allowed:${nodeKey}`);
  if (nodeType === "foreach" && Number(config.max_items || 0) * Number(config.parallelism || 1) > AUTOMATION_SAFETY_DEFAULTS.maxTotalIterationsPerRun) warnings.push(`foreach_nested_budget_may_be_exceeded:${nodeKey}`);
}

function detectObviousSelfTriggers(nodes, warnings) {
  const triggers = nodes.filter((n) => (n.node_type || n.nodeType) === "trigger").map((n) => n.config || {});
  const actions = nodes.filter((n) => (n.node_type || n.nodeType) === "action").map((n) => n.config || {});
  for (const trigger of triggers) {
    if (trigger.trigger_key === "contact.tag_added") {
      const triggerTag = String(trigger.tag || trigger.tag_name || "").toLowerCase();
      if (triggerTag && actions.some((a) => a.action_key === "contact.add_tag" && normalizeTags(a.tags || a.tag).map((t) => t.toLowerCase()).includes(triggerTag))) {
        warnings.push("possible_self_trigger:contact_tag");
      }
    }
    if (trigger.trigger_key === "pipeline.stage_changed" || trigger.trigger_key === "pipeline.stage_entered") {
      const toStage = String(trigger.to_stage_id || trigger.stage_id || "").toLowerCase();
      if (toStage && actions.some((a) => ["pipeline.move_stage", "pipeline.reopen"].includes(a.action_key) && String(a.stage_id || "").toLowerCase() === toStage)) {
        warnings.push("possible_self_trigger:pipeline_stage");
      }
    }
  }
}

function detectCycle(nodes, edges) {
  const ids = new Set(nodes.map((n) => n.id));
  const outgoing = new Map([...ids].map((id) => [id, []]));
  for (const edge of edges) {
    const source = edge.source_node_id || edge.sourceNodeId;
    const target = edge.target_node_id || edge.targetNodeId;
    if (ids.has(source) && ids.has(target)) outgoing.get(source).push(target);
  }
  const visiting = new Set();
  const visited = new Set();
  const dfs = (id) => {
    if (visiting.has(id)) return true;
    if (visited.has(id)) return false;
    visiting.add(id);
    for (const next of outgoing.get(id) || []) if (dfs(next)) return true;
    visiting.delete(id);
    visited.add(id);
    return false;
  };
  return [...ids].some(dfs);
}

async function saveDraftGraph(versionId, companyId, payload) {
  const db = await ctx.pool.connect();
  try {
    await db.query("BEGIN");
    await db.query(`DELETE FROM automation_edges WHERE version_id = $1 AND company_id = $2`, [versionId, companyId]);
    await db.query(`DELETE FROM automation_nodes WHERE version_id = $1 AND company_id = $2`, [versionId, companyId]);
    for (const node of payload.nodes || []) {
      await db.query(
        `INSERT INTO automation_nodes(id, version_id, company_id, node_key, node_type, category, title, config, position_x, position_y)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
        [
          node.id, versionId, companyId, node.node_key || node.nodeKey, node.node_type || node.nodeType,
          node.category || null, node.title || node.name || null, JSON.stringify(node.config || {}),
          Number(node.position_x ?? node.positionX ?? 0), Number(node.position_y ?? node.positionY ?? 0)
        ]
      );
    }
    for (const edge of payload.edges || []) {
      await db.query(
        `INSERT INTO automation_edges(id, version_id, company_id, source_node_id, target_node_id, source_port, target_port, label, priority, config)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
        [
          edge.id || randomUUID(), versionId, companyId, edge.source_node_id || edge.sourceNodeId, edge.target_node_id || edge.targetNodeId,
          edge.source_port || edge.sourcePort || null, edge.target_port || edge.targetPort || null, edge.label || null,
          Number(edge.priority || 0), JSON.stringify(edge.config || {})
        ]
      );
    }
    await db.query(`UPDATE automation_versions SET settings = $2::jsonb, updated_at = now() WHERE id = $1`, [versionId, JSON.stringify(payload.settings || {})]);
    await db.query("COMMIT");
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    db.release();
  }
}

async function publishAutomation(automationId, companyId, userId) {
  const db = await ctx.pool.connect();
  try {
    await db.query("BEGIN");
    const definition = (await db.query(`SELECT * FROM automation_definitions WHERE id = $1 AND company_id = $2 FOR UPDATE`, [automationId, companyId])).rows[0];
    if (!definition) {
      await db.query("ROLLBACK");
      return null;
    }
    let draft = definition.draft_version_id
      ? (await db.query(`SELECT * FROM automation_versions WHERE id = $1 AND company_id = $2 AND status = 'draft'`, [definition.draft_version_id, companyId])).rows[0]
      : null;
    if (!draft) {
      draft = (await db.query(
        `INSERT INTO automation_versions(automation_id, company_id, version_number, status, created_by_user_id)
         VALUES($1,$2,COALESCE((SELECT MAX(version_number) FROM automation_versions WHERE automation_id = $1),0) + 1,'draft',$3)
         RETURNING *`,
        [automationId, companyId, userId]
      )).rows[0];
      await db.query(`UPDATE automation_definitions SET draft_version_id = $2 WHERE id = $1`, [automationId, draft.id]);
    }
    const graph = await loadVersionGraph(draft.id, companyId);
    const validation = validateGraphPayload({ nodes: graph.nodes, edges: graph.edges, settings: graph.settings });
    if (!validation.valid) {
      await db.query("ROLLBACK");
      return validation;
    }
    const maxRow = (await db.query(`SELECT COALESCE(MAX(version_number),0)::int AS n FROM automation_versions WHERE automation_id = $1`, [automationId])).rows[0];
    const publishedNumber = Number(maxRow.n || 0) + 1;
    const published = (await db.query(
      `INSERT INTO automation_versions(automation_id, company_id, version_number, status, settings, created_by_user_id, published_at)
       SELECT automation_id, company_id, $3, 'published', settings, $4, now()
         FROM automation_versions WHERE id = $1 AND company_id = $2
       RETURNING *`,
      [draft.id, companyId, publishedNumber, userId]
    )).rows[0];
    await copyGraph(db, draft.id, published.id, companyId);
    await db.query(`UPDATE automation_versions SET status = 'retired', updated_at = now() WHERE automation_id = $1 AND company_id = $2 AND status = 'published' AND id <> $3`, [automationId, companyId, published.id]);
    const nextDraftNumber = published.version_number + 1;
    const newDraft = (await db.query(
      `INSERT INTO automation_versions(automation_id, company_id, version_number, status, settings, created_by_user_id)
       VALUES($1,$2,$3,'draft',$4::jsonb,$5) RETURNING *`,
      [automationId, companyId, nextDraftNumber, JSON.stringify(published.settings || {}), userId]
    )).rows[0];
    await copyGraph(db, published.id, newDraft.id, companyId);
    await db.query(
      `UPDATE automation_definitions SET active_version_id = $2, draft_version_id = $3, status = 'published',
          pause_until = NULL, updated_by_user_id = $4, updated_at = now()
        WHERE id = $1`,
      [automationId, published.id, newDraft.id, userId]
    );
    await db.query("COMMIT");
    return { valid: true, published_version: published, draft_version: newDraft, warnings: validation.warnings };
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    db.release();
  }
}

async function copyGraph(db, fromVersionId, toVersionId, companyId) {
  const idMap = new Map();
  const nodes = (await db.query(`SELECT * FROM automation_nodes WHERE version_id = $1 AND company_id = $2 ORDER BY created_at ASC`, [fromVersionId, companyId])).rows;
  for (const node of nodes) {
    const newId = randomUUID();
    idMap.set(node.id, newId);
    await db.query(
      `INSERT INTO automation_nodes(id, version_id, company_id, node_key, node_type, category, title, config, position_x, position_y)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
      [newId, toVersionId, companyId, node.node_key, node.node_type, node.category, node.title, JSON.stringify(node.config || {}), node.position_x, node.position_y]
    );
  }
  const edges = (await db.query(`SELECT * FROM automation_edges WHERE version_id = $1 AND company_id = $2`, [fromVersionId, companyId])).rows;
  for (const edge of edges) {
    await db.query(
      `INSERT INTO automation_edges(id, version_id, company_id, source_node_id, target_node_id, source_port, target_port, label, priority, config)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
      [randomUUID(), toVersionId, companyId, idMap.get(edge.source_node_id), idMap.get(edge.target_node_id), edge.source_port, edge.target_port, edge.label, edge.priority, JSON.stringify(edge.config || {})]
    );
  }
}

async function duplicateAutomation(automationId, companyId, userId) {
  const source = (await ctx.pool.query(`SELECT * FROM automation_definitions WHERE id = $1 AND company_id = $2`, [automationId, companyId])).rows[0];
  if (!source) return null;
  const db = await ctx.pool.connect();
  try {
    await db.query("BEGIN");
    const def = (await db.query(
      `INSERT INTO automation_definitions(company_id, folder_id, name, description, status, allow_manual_trigger, max_parallel_runs_per_subject, reentry_mode, cooldown_seconds, metadata, created_by_user_id, updated_by_user_id)
       VALUES($1,$2,$3,$4,'draft',$5,$6,$7,$8,$9::jsonb,$10,$10) RETURNING *`,
      [companyId, source.folder_id, `${source.name} Copy`, source.description, source.allow_manual_trigger, source.max_parallel_runs_per_subject, source.reentry_mode, source.cooldown_seconds, JSON.stringify(source.metadata || {}), userId]
    )).rows[0];
    const draft = (await db.query(
      `INSERT INTO automation_versions(automation_id, company_id, version_number, status, created_by_user_id, settings)
       VALUES($1,$2,1,'draft',$3,COALESCE((SELECT settings FROM automation_versions WHERE id = $4),'{}'::jsonb)) RETURNING *`,
      [def.id, companyId, userId, source.active_version_id || source.draft_version_id]
    )).rows[0];
    if (source.active_version_id || source.draft_version_id) await copyGraph(db, source.active_version_id || source.draft_version_id, draft.id, companyId);
    await db.query(`UPDATE automation_definitions SET draft_version_id = $2 WHERE id = $1`, [def.id, draft.id]);
    await db.query("COMMIT");
    return { ...def, draft_version_id: draft.id };
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    db.release();
  }
}

function workerId() {
  return `${process.pid}:${Date.now()}`;
}

async function processAutomationEvents() {
  if (!ctx?.pool) return;
  const db = await ctx.pool.connect();
  let events = [];
  const leaseOwner = workerId();
  try {
    await db.query("BEGIN");
    events = (await db.query(
      `SELECT * FROM automation_events
        WHERE processing_status IN ('pending','failed')
          AND processed_at IS NULL
          AND (next_attempt_at IS NULL OR next_attempt_at <= now())
          AND (locked_at IS NULL OR locked_at < now() - ($2::int * interval '1 second'))
        ORDER BY occurred_at ASC, created_at ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED`,
      [AUTOMATION_LIMITS.eventBatchSize, AUTOMATION_SAFETY_DEFAULTS.processorLeaseSeconds]
    )).rows;
    if (events.length) await db.query(`UPDATE automation_events SET processing_status = 'processing', locked_at = now(), locked_by = $2, attempt_count = attempt_count + 1 WHERE id = ANY($1::uuid[])`, [events.map((e) => e.id), leaseOwner]);
    await db.query("COMMIT");
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    db.release();
    console.error("[automations] event lock failed", e?.message || e);
    return;
  }
  db.release();
  for (const event of events) {
    try {
      await applyRunMonitorsForEvent(event);
      await wakeEventWaits(event);
      await startRunsForEvent(event);
      await ctx.pool.query(`UPDATE automation_events SET processing_status = 'processed', processed_at = now(), error = NULL, locked_at = NULL, locked_by = NULL WHERE id = $1`, [event.id]);
    } catch (e) {
      console.error("[automations] event processing failed", { id: event.id, eventType: event.event_type, message: e?.message });
      const attempts = Number(event.attempt_count || 0) + 1;
      if (attempts >= AUTOMATION_SAFETY_DEFAULTS.eventMaxAttempts) {
        await ctx.pool.query(`UPDATE automation_events SET processing_status = 'dead_letter', failed_at = now(), error = $2, locked_at = NULL, locked_by = NULL WHERE id = $1`, [event.id, (e?.message || "event_failed").slice(0, 1000)]);
        await createDeadLetter({ companyId: event.company_id, sourceType: "event", sourceId: event.id, eventType: event.event_type, subjectType: event.subject_type, subjectId: event.subject_id, attempts, errorCode: "event_processing_failed", errorMessage: e?.message || "Event processing failed" });
      } else {
        const delay = Math.min(300, 5 * Math.pow(2, attempts - 1));
        await ctx.pool.query(`UPDATE automation_events SET processing_status = 'failed', error = $2, next_attempt_at = now() + ($3::int * interval '1 second'), locked_at = NULL, locked_by = NULL WHERE id = $1`, [event.id, (e?.message || "event_failed").slice(0, 1000), delay]);
      }
    }
  }
}

async function startRunsForEvent(event) {
  const { rows } = await ctx.pool.query(
    `SELECT DISTINCT d.*, v.id AS version_id
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
       JOIN companies c ON c.id = d.company_id
      WHERE d.company_id = $1
        AND c.automations_enabled = true
        AND c.automation_emergency_stopped_at IS NULL
        AND d.status = 'published'
        AND (d.pause_until IS NULL OR d.pause_until <= now())
        AND (
          n.config->>'trigger_key' = $2
          OR (n.config->'event_types') ? $2
        )`,
    [event.company_id, event.event_type]
  );
  if (!(await companyRunQuotaAllows(event.company_id))) throw new AutomationError("rate_limited", "Company automation start quota reached", { retryable: true });
  for (const automation of rows) {
    const triggers = (await ctx.pool.query(
      `SELECT * FROM automation_nodes WHERE version_id = $1 AND company_id = $2 AND node_type = 'trigger'`,
      [automation.version_id, event.company_id]
    )).rows;
    if (!triggers.some((node) => triggerMatchesEvent(node, event))) continue;
    const startDecision = await canStartRun(automation, event);
    if (!startDecision.allowed) {
      if (startDecision.retryable) throw new AutomationError(startDecision.code || "automation_concurrency_full", startDecision.message || "Automation concurrency full", { retryable: true });
      continue;
    }
    const reentryKey = await resolveReentryKey(automation, event);
    const run = await createRun({
      companyId: event.company_id,
      automationId: automation.id,
      versionId: automation.version_id,
      triggerEventId: event.id,
      subjectType: event.subject_type,
      subjectId: event.subject_id,
      reentryKey,
      depth: 0,
      dryRun: false
    });
    await installRunMonitors(run);
    await logRun(run, null, "info", "trigger.matched", `Trigger matched ${event.event_type}`, { event_id: event.id });
    await runAutomation(run.id);
  }
}

async function canStartRun(automation, event) {
  const mode = automation.reentry_mode || automation.metadata?.reentry_mode || "after_previous_completion";
  const reentryKey = await resolveReentryKey(automation, event);
  if (!reentryKey || mode === "unlimited") return { allowed: true };
  const baseParams = [automation.company_id, automation.id, reentryKey];
  const maxAutomationRuns = Number(automation.max_active_runs || automation.metadata?.max_active_runs || AUTOMATION_SAFETY_DEFAULTS.maxActiveRunsPerAutomation);
  const activeAutomationRuns = await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND status IN ('queued','running','waiting','paused')`, [automation.company_id, automation.id]);
  if (maxAutomationRuns > 0 && Number(activeAutomationRuns.rows[0].count) >= maxAutomationRuns) {
    return { allowed: false, retryable: (automation.concurrency_policy || "queue") === "queue", code: "automation_concurrency_full" };
  }
  const maxSubjectRuns = Number(automation.max_active_runs_per_subject || automation.max_parallel_runs_per_subject || automation.metadata?.max_active_runs_per_subject || 0);
  if (maxSubjectRuns > 0) {
    const activeSubjectRuns = await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND reentry_key = $3 AND status IN ('queued','running','waiting','paused')`, baseParams);
    if (Number(activeSubjectRuns.rows[0].count) >= maxSubjectRuns) return { allowed: false, retryable: (automation.subject_concurrency_policy || "queue") === "queue", code: "subject_concurrency_full" };
  }
  if (mode === "once_ever_per_subject") {
    const existing = await ctx.pool.query(`SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND reentry_key = $3 LIMIT 1`, baseParams);
    return { allowed: !existing.rowCount };
  }
  if (mode === "once_while_active") {
    const active = await ctx.pool.query(`SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND reentry_key = $3 AND status IN ('queued','running','waiting','paused') LIMIT 1`, baseParams);
    return { allowed: !active.rowCount };
  }
  if (automation.cooldown_seconds) {
    const basis = automation.cooldown_basis === "started_at" ? "created_at" : "COALESCE(completed_at, updated_at, created_at)";
    const recent = await ctx.pool.query(
      `SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND reentry_key = $3 AND ${basis} > now() - ($4::int * interval '1 second') LIMIT 1`,
      [...baseParams, automation.cooldown_seconds]
    );
    if (recent.rowCount) return { allowed: false };
  }
  if (mode === "after_previous_completion") {
    const active = await ctx.pool.query(`SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND reentry_key = $3 AND status IN ('queued','running','waiting','paused') LIMIT 1`, baseParams);
    return { allowed: !active.rowCount, retryable: true, code: "subject_run_active" };
  }
  return { allowed: true };
}

function normalReentryKey(subjectType, subjectId, fallbackId = null) {
  return subjectId ? `${subjectType || "generic"}:${subjectId}` : `event:${fallbackId || randomUUID()}`;
}

async function resolveReentryKey(automation, event) {
  const template = automation.metadata?.reentry_key_template || automation.metadata?.composite_reentry_key;
  if (!template) return normalReentryKey(event.subject_type, event.subject_id, event.id);
  const context = {
    event: { id: event.id, type: event.event_type, payload: event.payload || {}, subject_type: event.subject_type, subject_id: event.subject_id },
    subject: { type: event.subject_type, id: event.subject_id }
  };
  const resolved = resolveTemplate(template, context).trim();
  return resolved ? `custom:${resolved}` : normalReentryKey(event.subject_type, event.subject_id, event.id);
}

async function companyRunQuotaAllows(companyId) {
  const company = (await ctx.pool.query(`SELECT automation_run_starts_per_minute FROM companies WHERE id = $1`, [companyId])).rows[0] || {};
  const limit = Number(company.automation_run_starts_per_minute || AUTOMATION_SAFETY_DEFAULTS.runStartsPerMinute);
  const recent = (await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE company_id = $1 AND created_at > now() - interval '1 minute'`, [companyId])).rows[0]?.count || 0;
  return Number(recent) < limit;
}

async function installRunMonitors(run) {
  const version = (await ctx.pool.query(`SELECT settings FROM automation_versions WHERE id = $1`, [run.automation_version_id])).rows[0];
  const settings = version?.settings || {};
  const monitors = [];
  for (const item of normalizeMonitorSettings(settings.stop_conditions || settings.stopConditions, "stop")) monitors.push(item);
  for (const item of normalizeMonitorSettings(settings.goals || settings.goal_conditions || settings.goalConditions, "goal")) monitors.push(item);
  for (const monitor of monitors) {
    await ctx.pool.query(
      `INSERT INTO automation_run_monitors(run_id, automation_version_id, monitor_type, event_type, monitor_key, mode, behavior, match_subject_type, match_subject_id, config)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
       ON CONFLICT(run_id, monitor_type, monitor_key, event_type) DO NOTHING`,
      [run.id, run.automation_version_id, monitor.monitor_type, monitor.event_type, monitor.monitor_key, monitor.mode, monitor.behavior, monitor.match_subject_type || run.subject_type, monitor.match_subject_id || run.subject_id, JSON.stringify(monitor.config || {})]
    );
  }
}

function normalizeMonitorSettings(value, type) {
  const raw = Array.isArray(value) ? value : [];
  return raw.flatMap((item, index) => {
    const preset = monitorPreset(item.preset || item.key || item.event_type || item.eventType);
    const events = item.event_types || item.eventTypes || (preset ? preset.event_types : [item.event_type || item.eventType].filter(Boolean));
    return events.map((eventType) => ({
      monitor_type: type,
      event_type: eventType,
      monitor_key: stablePortId(item.monitor_key || item.goal_key || item.key || item.preset || `${type}_${index}`),
      mode: item.mode || "any",
      behavior: type === "goal" ? (item.behavior || "record") : "stop",
      match_subject_type: item.match_subject_type || item.subject_type || null,
      match_subject_id: item.match_subject_id || item.subject_id || null,
      config: { ...item, preset: item.preset || preset?.key || null }
    }));
  }).filter((m) => m.event_type);
}

function monitorPreset(key) {
  const presets = {
    customer_replies: { key: "customer_replies", event_types: ["sms.reply_received", "sms.received"] },
    customer_opted_out: { key: "customer_opted_out", event_types: ["sms.opted_out"] },
    opportunity_won: { key: "opportunity_won", event_types: ["pipeline.won"] },
    opportunity_lost: { key: "opportunity_lost", event_types: ["pipeline.lost"] },
    contact_deleted: { key: "contact_deleted", event_types: ["contact.deleted"] },
    payment_received: { key: "payment_received", event_types: ["payment.succeeded"] },
    job_completed: { key: "job_completed", event_types: ["job.completed"] },
    service_plan_canceled: { key: "service_plan_canceled", event_types: ["service_plan.canceled"] }
  };
  return presets[String(key || "").replace(/[.-]/g, "_")] || null;
}

async function applyRunMonitorsForEvent(event) {
  const { rows } = await ctx.pool.query(
    `SELECT m.*, r.company_id, r.automation_id, r.status, r.subject_type AS run_subject_type, r.subject_id AS run_subject_id
       FROM automation_run_monitors m
       JOIN automation_runs r ON r.id = m.run_id
      WHERE m.status = 'active'
        AND m.event_type = $1
        AND r.company_id = $2
        AND r.status IN ('queued','running','waiting','paused')`,
    [event.event_type, event.company_id]
  );
  for (const monitor of rows) {
    if (!monitorEventSubjectMatches(monitor, event)) continue;
    const claimed = (await ctx.pool.query(
      `UPDATE automation_run_monitors SET status = 'matched', matched_event_id = $2, matched_at = now(), updated_at = now()
        WHERE id = $1 AND status = 'active' RETURNING *`,
      [monitor.id, event.id]
    )).rows[0];
    if (!claimed) continue;
    const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [monitor.run_id])).rows[0];
    if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) continue;
    if (monitor.monitor_type === "goal") {
      await ctx.pool.query(
        `INSERT INTO automation_run_goals(run_id, node_id, goal_key, metadata, scope_key)
         VALUES($1,NULL,$2,$3::jsonb,'root') ON CONFLICT DO NOTHING`,
        [run.id, monitor.monitor_key, JSON.stringify({ event_id: event.id, event_type: event.event_type, monitor: monitor.config || {} })]
      );
      if (monitor.behavior !== "stop") continue;
    }
    await stopRun(run, "stop_condition", monitor.config?.label || monitor.config?.preset || monitor.monitor_key, monitor.monitor_key);
    await cancelRunContinuations(run.id);
  }
}

function monitorEventSubjectMatches(monitor, event) {
  const payload = event.payload || {};
  const targets = [event.subject_id, payload.contact_id, payload.conversation_id, payload.payment_id, payload.quote_id, payload.job_id, payload.service_plan_id, payload.route_id, payload.pin_id].filter(Boolean).map(String);
  return !monitor.match_subject_id || targets.includes(String(monitor.match_subject_id)) || (String(monitor.run_subject_type || "") === String(event.subject_type || "") && String(monitor.run_subject_id || "") === String(event.subject_id || ""));
}

async function startManualRun(automationId, companyId, userId, body) {
  const automation = (await ctx.pool.query(
    `SELECT d.*, v.id AS version_id FROM automation_definitions d JOIN automation_versions v ON v.id = d.active_version_id
      WHERE d.id = $1 AND d.company_id = $2 AND v.status = 'published'`,
    [automationId, companyId]
  )).rows[0];
  if (!automation || !automation.allow_manual_trigger) return null;
  await validateSubject(companyId, body.subject_type || "generic", body.subject_id || null);
  const eventId = await emitAutomationEvent({
    companyId,
    eventType: "manual",
    subjectType: body.subject_type || "generic",
    subjectId: body.subject_id || null,
    actorUserId: userId,
    source: "manual",
    payload: { manual: true, input: body.input || {} }
  });
  const run = await createRun({
    companyId,
    automationId,
    versionId: automation.version_id,
    triggerEventId: eventId,
    subjectType: body.subject_type || "generic",
    subjectId: body.subject_id || null,
    manualUserId: userId,
    dryRun: !!body.dry_run,
    reentryKey: normalReentryKey(body.subject_type || "generic", body.subject_id || eventId, eventId),
    depth: 0
  });
  await installRunMonitors(run);
  await logRun(run, null, "info", body.dry_run ? "run.dry_start" : "run.manual_start", "Manual run started", { subject_type: body.subject_type, subject_id: body.subject_id });
  setImmediate(() => runAutomation(run.id).catch((e) => console.error("[automations] manual run wake failed", e?.message || e)));
  return run;
}

async function startDraftTestRun(automationId, companyId, userId, body) {
  const automation = (await ctx.pool.query(
    `SELECT d.*, v.id AS version_id
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.draft_version_id
      WHERE d.id = $1 AND d.company_id = $2 AND v.status = 'draft'`,
    [automationId, companyId]
  )).rows[0];
  if (!automation) return null;
  await validateSubject(companyId, body.subject_type || "generic", body.subject_id || null);
  const graph = await loadVersionGraph(automation.version_id, companyId);
  const firstTrigger = graph.nodes.find((node) => node.node_type === "trigger");
  const triggerKey = body.trigger_key || firstTrigger?.config?.trigger_key || "manual";
  const eventId = await emitAutomationEvent({
    companyId,
    eventType: triggerKey,
    subjectType: body.subject_type || firstTrigger?.config?.subject_type || "generic",
    subjectId: body.subject_id || null,
    actorUserId: userId,
    source: "manual",
    dedupeKey: `draft_test:${automationId}:${userId}:${randomUUID()}`,
    payload: { manual: true, draft_test: true, input: body.input || {}, ...(body.payload || {}) }
  });
  const run = await createRun({
    companyId,
    automationId,
    versionId: automation.version_id,
    triggerEventId: eventId,
    subjectType: body.subject_type || "generic",
    subjectId: body.subject_id || null,
    manualUserId: userId,
    dryRun: true,
    reentryKey: `draft_test:${automationId}:${eventId}`,
    depth: 0
  });
  await logRun(run, null, "info", "run.draft_test_start", "Draft test run started", { subject_type: body.subject_type, subject_id: body.subject_id, trigger_key: triggerKey });
  setImmediate(() => runAutomation(run.id).catch((e) => console.error("[automations] draft test wake failed", e?.message || e)));
  return run;
}

async function createRun({ companyId, automationId, versionId, triggerEventId = null, subjectType = null, subjectId = null, manualUserId = null, dryRun = false, parentRunId = null, parentNodeId = null, rootRunId = null, depth = 0, reentryKey = null, recoveredFromRunId = null, recoveredFromRunNodeId = null, recoveryStartNodeId = null, recoveryScopeKey = null }) {
  const { rows } = await ctx.pool.query(
    `INSERT INTO automation_runs(company_id, automation_id, automation_version_id, trigger_event_id, subject_type, subject_id, status, started_at, manual_started_by_user_id, dry_run, parent_run_id, parent_node_id, root_run_id, depth, reentry_key, recovered_from_run_id, recovered_from_run_node_id, recovery_start_node_id, recovery_scope_key)
     VALUES($1,$2,$3,$4,$5,$6,'queued',now(),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
    [companyId, automationId, versionId, triggerEventId, subjectType, subjectId ? String(subjectId) : null, manualUserId, dryRun, parentRunId, parentNodeId, rootRunId, depth, reentryKey || normalReentryKey(subjectType, subjectId, triggerEventId), recoveredFromRunId, recoveredFromRunNodeId, recoveryStartNodeId, recoveryScopeKey]
  );
  if (!rootRunId) await ctx.pool.query(`UPDATE automation_runs SET root_run_id = id WHERE id = $1`, [rows[0].id]);
  return { ...rows[0], root_run_id: rows[0].root_run_id || rows[0].id };
}

async function runAutomation(runId, resumeFromNodeId = null, incomingPort = null, scopeKey = "root") {
  let run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [runId])).rows[0];
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  if (run.current_node_count >= AUTOMATION_LIMITS.maxNodesPerRun) return failRun(run, "node_limit", "Maximum node executions reached");
  await ctx.pool.query(`UPDATE automation_runs SET status = 'running', updated_at = now() WHERE id = $1 AND status IN ('queued','waiting','running')`, [runId]);
  run = { ...run, status: "running" };
  const graph = await loadGraph(run.automation_version_id, run.company_id);
  let startNodes = [];
  if (resumeFromNodeId) {
    startNodes = graph.edges.filter((e) => e.source_node_id === resumeFromNodeId && portMatches(e.source_port, incomingPort || "default")).sort(edgeSort).map((e) => graph.nodeById.get(e.target_node_id));
  } else {
    for (const n of graph.nodes) {
      if (n.node_type === "trigger" && await triggerMatchesRunAsync(n, run)) startNodes.push(n);
    }
  }
  if (!startNodes.length && !resumeFromNodeId) {
    await completeRunIfIdle(run);
    return;
  }
  for (const node of startNodes.filter(Boolean)) {
    await executeFromNode(run.id, node.id, scopeKey);
  }
  if (scopeKey === "root") await completeRunIfIdle((await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [runId])).rows[0]);
}

async function executeFromNode(runId, nodeId, scopeKey = "root", arrival = null) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [runId])).rows[0];
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  const graph = await loadGraph(run.automation_version_id, run.company_id);
  const node = graph.nodeById.get(nodeId);
  if (!node) return;
  if (node.node_type === "note") return;
  if (await shouldStopRun(run)) return stopRun(run, "stop_condition", "Global stop condition matched");
  await enforceRunBudget(run, node, scopeKey);
  const previous = await ctx.pool.query(
    `SELECT COUNT(*)::int AS count, COUNT(*) FILTER (WHERE status = 'completed')::int AS completed FROM automation_run_nodes WHERE run_id = $1 AND node_key = $2 AND scope_key = $3`,
    [runId, node.node_key, scopeKey]
  );
  if (Number(previous.rows[0].completed) > 0 && !node.config?.repeatable && !["merge", "foreach"].includes(node.node_type)) {
    await traverse(run, graph, node, "default", scopeKey);
    return;
  }
  const attempt = Number(previous.rows[0].count) + 1;
  if (attempt > AUTOMATION_LIMITS.maxNodeAttempts) return failRun(run, "node_attempt_limit", `Node ${node.node_key} exceeded attempt limit`);
  const runNode = await beginRunNode(run, node, attempt, scopeKey);
  try {
    const result = await executeNode(run, node, runNode, scopeKey, arrival);
    if (result?.waiting) return;
    if (result?.stoppedPath) {
      await finishRunNode(runNode.id, "completed", result?.output || {});
      return;
    }
    if (result?.stoppedRun) {
      await finishRunNode(runNode.id, "completed", result?.output || {});
      return;
    }
    await finishRunNode(runNode.id, "completed", result?.output || {});
    await ctx.pool.query(`UPDATE automation_runs SET current_node_count = current_node_count + 1, updated_at = now() WHERE id = $1`, [run.id]);
    if (Array.isArray(result?.ports)) {
      for (const port of result.ports) await traverse(run, graph, node, port, scopeKey);
    } else {
      await traverse(run, graph, node, result?.port || "default", scopeKey);
    }
  } catch (e) {
    const classified = classifyAutomationError(e);
    await logRun(run, node, "error", "node.failed", `Node ${node.title || node.node_key} failed`, { error: classified.message, error_code: classified.code, error_class: classified.errorClass, retryable: classified.retryable, scope_key: scopeKey });
    const retryPolicy = retryPolicyForNode(node);
    if (attempt < retryPolicy.maxAttempts && classified.retryable && isRetrySafe(node)) {
      const delay = retryDelaySeconds(retryPolicy, attempt, run.id, node.id, scopeKey);
      const retryAt = new Date(Date.now() + delay * 1000).toISOString();
      await finishRunNode(runNode.id, "waiting_retry", {}, classified.code, classified.message, { errorClass: classified.errorClass, retryable: true, nextRetryAt: retryAt, metadata: { delay_seconds: delay } });
      await createWait(run, node, "duration", { resume_at: retryAt, resume_port: "default", scope_key: scopeKey, retry: true });
      return;
    }
    await finishRunNode(runNode.id, "failed", {}, classified.code, classified.message, { errorClass: classified.errorClass, retryable: classified.retryable });
    const onError = node.config?.on_error || (node.config?.continue_on_error ? "continue" : "stop");
    if (onError === "error_path") {
      await ctx.pool.query(
        `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
         ON CONFLICT(run_id, name) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [run.id, "error", JSON.stringify({ code: classified.code, message: classified.message, retryable: classified.retryable, node_id: node.id, attempt, details_safe: redact(classified.details || {}) })]
      );
      await traverse(run, graph, node, "error", scopeKey);
      return;
    }
    if (onError === "continue" || node.config?.continue_on_error) {
      await traverse(run, graph, node, "error", scopeKey);
      return;
    }
    await failRun(run, "node_failed", e?.message || "Node failed");
  }
  if (scopeKey !== "root") await completeIterationScopeIfIdle(run.id, scopeKey);
}

async function loadGraph(versionId, companyId) {
  const nodes = (await ctx.pool.query(`SELECT * FROM automation_nodes WHERE version_id = $1 AND company_id = $2`, [versionId, companyId])).rows;
  const edges = (await ctx.pool.query(`SELECT * FROM automation_edges WHERE version_id = $1 AND company_id = $2`, [versionId, companyId])).rows;
  return { nodes, edges, nodeById: new Map(nodes.map((n) => [n.id, n])), edgesBySource: edges.reduce((m, e) => ((m[e.source_node_id] ||= []).push(e), m), {}) };
}

function triggerMatchesRun(node, run) {
  if (!run.trigger_event_id && node.config?.trigger_key === "manual") return true;
  return false;
}

async function triggerMatchesRunAsync(node, run) {
  if (!run.trigger_event_id) return node.config?.trigger_key === "manual";
  const event = (await ctx.pool.query(`SELECT * FROM automation_events WHERE id = $1`, [run.trigger_event_id])).rows[0];
  return event ? triggerMatchesEvent(node, event) : false;
}

function triggerMatchesEvent(node, event) {
  const config = node.config || {};
  const key = config.trigger_key;
  if (!key) return false;
  const events = Array.isArray(config.event_types) ? config.event_types : [key];
  if (!events.includes(event.event_type)) return false;
  const payload = event.payload || {};
  if (payload.trigger_node_id && payload.trigger_node_id !== node.id) return false;
  if (payload.origin_run_id && config.allow_automation_origin !== true) return false;
  if (Array.isArray(config.sources) && config.sources.length) {
    const source = String(payload.source || event.source || "").toLowerCase();
    if (!config.sources.map((s) => String(s).toLowerCase()).includes(source)) return false;
  }
  if (config.field) {
    const fields = changedFields(payload);
    const wanted = String(config.field);
    const changed = fields.find((f) => f.field === wanted);
    if (!changed) return false;
    if (config.from != null && config.from !== "" && !looseEqual(changed.old_value, config.from)) return false;
    if (config.to != null && config.to !== "" && !looseEqual(changed.new_value, config.to)) return false;
  }
  const triggerTag = config.tag || (Array.isArray(config.tags) && config.tags.length === 1 ? config.tags[0] : null);
  if (triggerTag || (Array.isArray(config.tags) && config.tags.length)) {
    const eventTags = normalizeTags(payload.tags || payload.added_tags || payload.removed_tags || payload.tag);
    const wanted = normalizeTags(config.tags || triggerTag).map((t) => t.toLowerCase());
    if (!wanted.length) return true;
    const actual = eventTags.map((t) => t.toLowerCase());
    const mode = config.tag_match || "one_of";
    if (mode === "all" && !wanted.every((t) => actual.includes(t))) return false;
    if (mode !== "all" && !wanted.some((t) => actual.includes(t))) return false;
  }
  const stageIds = Array.isArray(config.stage_ids) ? config.stage_ids.filter(Boolean) : [];
  const eventStageId = payload.stage_id || payload.new_stage_id || payload.to_stage_id;
  if (stageIds.length && !stageIds.includes(eventStageId)) return false;
  if (config.from_stage_id && config.from_stage_id !== "any" && config.from_stage_id !== (payload.previous_stage_id || payload.old_stage_id || payload.from_stage_id)) return false;
  if (config.to_stage_id && config.to_stage_id !== "any" && config.to_stage_id !== eventStageId) return false;
  if (key.startsWith("job.")) {
    if (Array.isArray(config.worker_user_ids) && config.worker_user_ids.length) {
      const workers = [...(payload.worker_ids_added || []), ...(payload.added || []), ...(payload.worker_user_ids || [])];
      if (!config.worker_user_ids.some((id) => workers.includes(id))) return false;
    }
    if (Array.isArray(config.sales_user_ids) && config.sales_user_ids.length) {
      const sales = [...(payload.salesperson_ids_added || []), ...(payload.added || []), ...(payload.sales_user_ids || [])];
      if (!config.sales_user_ids.some((id) => sales.includes(id))) return false;
    }
    if (Array.isArray(config.services) && config.services.length) {
      const services = normalizeServiceItems(payload.services || payload.added_services || payload.service_items || []).map((s) => s.name.toLowerCase());
      if (!config.services.some((s) => services.includes(String(s).toLowerCase()))) return false;
    }
  }
  if (key.startsWith("sms.")) {
    if (config.known_contact === true && !payload.contact_id) return false;
    if (config.known_contact === false && payload.contact_id) return false;
    if (Array.isArray(config.keywords) && config.keywords.length) {
      if (!matchesTextKeywords(payload.body || payload.message_body || "", config)) return false;
    }
    const triggerNumber = normalizePhone(config.external_number || config.phone || "");
    if (triggerNumber && triggerNumber !== normalizePhone(payload.external_number || payload.external_phone_number || payload.from_number || payload.to_number)) return false;
  }
  if (key.startsWith("call.")) {
    if (config.direction && config.direction !== "any" && config.direction !== payload.direction) return false;
    if (config.known_contact === true && !payload.contact_id) return false;
    if (config.known_contact === false && payload.contact_id) return false;
    if (Number(config.threshold_seconds || 0) > 0 && Number(payload.duration_seconds || 0) < Number(config.threshold_seconds)) return false;
  }
  if (key.startsWith("voicemail.")) {
    if (config.known_contact === true && !payload.contact_id) return false;
    if (config.known_contact === false && payload.contact_id) return false;
    if (Number(config.min_duration_seconds || 0) > 0 && Number(payload.duration_seconds || payload.duration || 0) < Number(config.min_duration_seconds)) return false;
  }
  if (key.startsWith("internal.")) {
    if (config.channel_id && config.channel_id !== payload.channel_id) return false;
    if (config.sender_user_id && config.sender_user_id !== payload.sender_user_id) return false;
    if (Array.isArray(config.keywords) && config.keywords.length) {
      if (!matchesTextKeywords(payload.body || payload.message_body || "", config)) return false;
    }
  }
  if (key.startsWith("quote.")) {
    if (Array.isArray(config.statuses) && config.statuses.length && !config.statuses.includes(payload.status)) return false;
    if (config.min_total_cents != null && Number(payload.total_cents || 0) < Number(config.min_total_cents)) return false;
    if (config.max_total_cents != null && Number(payload.total_cents || 0) > Number(config.max_total_cents)) return false;
  }
  if (key.startsWith("payment.")) {
    if (config.status && config.status !== payload.status) return false;
    if (config.min_amount_cents != null && Number(payload.amount_cents || 0) < Number(config.min_amount_cents)) return false;
    if (config.max_amount_cents != null && Number(payload.amount_cents || 0) > Number(config.max_amount_cents)) return false;
  }
  if (key.startsWith("service_plan.")) {
    if (Array.isArray(config.statuses) && config.statuses.length && !config.statuses.includes(payload.status || payload.subscription_status)) return false;
  }
  if (key.startsWith("map.") || key.startsWith("canvass.")) {
    if (Array.isArray(config.statuses) && config.statuses.length && !config.statuses.includes(payload.status || payload.new_status)) return false;
    if (config.from_status && config.from_status !== "any" && config.from_status !== payload.old_status) return false;
    if (config.to_status && config.to_status !== "any" && config.to_status !== (payload.new_status || payload.status)) return false;
    if (config.list_id && config.list_id !== (payload.list_id || payload.new_list_id)) return false;
    if (config.known_contact === true && !payload.contact_id) return false;
    if (config.known_contact === false && payload.contact_id) return false;
  }
  if (key.startsWith("route.")) {
    if (Array.isArray(config.route_statuses) && config.route_statuses.length && !config.route_statuses.includes(payload.status)) return false;
    if (config.assigned_user_id && config.assigned_user_id !== payload.assigned_user_id) return false;
  }
  if (key.startsWith("employee.")) {
    if (config.employee_id && config.employee_id !== payload.employee_id) return false;
    if (config.role && config.role !== payload.role) return false;
    if (config.active != null && Boolean(config.active) !== Boolean(payload.active)) return false;
  }
  if (key.startsWith("time_clock.")) {
    if (config.employee_id && config.employee_id !== payload.employee_id) return false;
  }
  return true;
}

function matchesTextKeywords(text, config) {
  const raw = (text || "").toString();
  const source = config.case_sensitive ? raw : raw.toLowerCase();
  const keywords = (Array.isArray(config.keywords) ? config.keywords : [])
    .map((k) => (config.case_sensitive ? String(k) : String(k).toLowerCase()).trim())
    .filter(Boolean);
  if (!keywords.length) return true;
  const mode = config.matching_mode || config.mode || "contains";
  const matcher = (keyword) => {
    if (mode === "equals") return source === keyword;
    if (mode === "starts_with") return source.startsWith(keyword);
    if (mode === "ends_with") return source.endsWith(keyword);
    return source.includes(keyword);
  };
  return (config.match_all || config.keyword_match === "all")
    ? keywords.every(matcher)
    : keywords.some(matcher);
}

function changedFields(payload) {
  if (!Array.isArray(payload?.changed_fields)) return [];
  return payload.changed_fields.map((item) => typeof item === "string" ? { field: item } : item).filter((item) => item?.field);
}

async function beginRunNode(run, node, attempt, scopeKey = "root") {
  const context = await buildRunContext(run, { slim: true, scopeKey });
  const { rows } = await ctx.pool.query(
    `INSERT INTO automation_run_nodes(run_id, node_id, node_key, status, scope_key, attempt_number, input_snapshot, started_at, locked_at, locked_by)
     VALUES($1,$2,$3,'running',$4,$5,$6::jsonb,now(),now(),$7) RETURNING *`,
    [run.id, node.id, node.node_key, scopeKey, attempt, JSON.stringify(safeSnapshot(context)), workerId()]
  );
  await logRun(run, node, "info", "node.started", `Started ${node.title || node.node_key}`, { scope_key: scopeKey });
  return rows[0];
}

async function finishRunNode(id, status, output, errorCode = null, errorMessage = null, extra = {}) {
  await ctx.pool.query(
    `UPDATE automation_run_nodes SET status = $2, output_snapshot = $3::jsonb, error_code = $4, error_message = $5, error_class = $6, retryable = $7, next_retry_at = $8::timestamptz, locked_at = NULL, locked_by = NULL, completed_at = CASE WHEN $2 IN ('completed','failed','skipped','canceled') THEN now() ELSE completed_at END, updated_at = now()
      WHERE id = $1`,
    [id, status, JSON.stringify(safeJson(output || {})), errorCode, errorMessage, extra.errorClass || null, extra.retryable ?? null, extra.nextRetryAt || null]
  );
  const row = (await ctx.pool.query(`SELECT * FROM automation_run_nodes WHERE id = $1`, [id])).rows[0];
  if (row) {
    await ctx.pool.query(
      `INSERT INTO automation_run_node_attempts(run_id, run_node_id, node_id, node_key, scope_key, attempt_number, status, started_at, completed_at, error_code, error_class, error_message, retryable, next_retry_at, metadata)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)`,
      [row.run_id, row.id, row.node_id, row.node_key, row.scope_key || "root", row.attempt_number, status, row.started_at, row.completed_at || new Date(), errorCode, extra.errorClass || null, errorMessage, extra.retryable ?? null, extra.nextRetryAt || null, JSON.stringify(redact(extra.metadata || {}))]
    );
  }
}

async function executeNode(run, node, runNode, scopeKey = "root", arrival = null) {
  if (node.node_type === "trigger") {
    await logRun(run, node, "info", "trigger.started", "Trigger node entered", {});
    return { port: "default", output: { triggered: true } };
  }
  if (node.node_type === "condition") {
    const context = await buildRunContext(run, { scopeKey });
    const result = evaluateCondition(node.config?.condition || node.config, context);
    await logRun(run, node, "info", result ? "condition.true" : "condition.false", `Condition evaluated ${result ? "true" : "false"}`, {});
    return { port: result ? "true" : "false", output: { result } };
  }
  if (node.node_type === "branch") {
    const context = await buildRunContext(run, { scopeKey });
    const value = resolveTemplate(node.config?.input || "", context).trim();
    const branches = Array.isArray(node.config?.branches) ? node.config.branches.map(String) : [];
    const port = branches.includes(value) ? value : "default";
    await logRun(run, node, "info", "branch.selected", `Branch selected ${port}`, { value });
    return { port, output: { value, port } };
  }
  if (node.node_type === "wait") {
    const wait = await createWaitForNode(run, node, scopeKey);
    await ctx.pool.query(`UPDATE automation_run_nodes SET status = 'waiting', output_snapshot = $2::jsonb, updated_at = now() WHERE id = $1`, [runNode.id, JSON.stringify({ wait_id: wait.id })]);
    await ctx.pool.query(`UPDATE automation_runs SET status = 'waiting', updated_at = now() WHERE id = $1`, [run.id]);
    await logRun(run, node, "info", "wait.created", "Wait created", { wait_id: wait.id, wait_type: wait.wait_type, resume_at: wait.resume_at, event_type: wait.event_type, timeout_at: wait.timeout_at });
    return { waiting: true };
  }
  if (node.node_type === "utility" && (node.config?.utility_key === "variable.set" || node.config?.action_key === "variable.set")) {
    const context = await buildRunContext(run, { scopeKey });
    const name = (node.config?.name || "").toString().trim();
    if (!name) throw new Error("variable_name_required");
    const value = resolveTemplate(node.config?.value ?? "", context);
    await ctx.pool.query(
      `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
       ON CONFLICT(run_id, name) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [run.id, name, JSON.stringify(value)]
    );
    return { port: "default", output: { name, value } };
  }
  if (node.node_type === "foreach") return executeForeachNode(run, node, scopeKey);
  if (node.node_type === "merge") return executeMergeNode(run, node, scopeKey, arrival);
  if (node.node_type === "parallel") return executeParallelNode(run, node);
  if (node.node_type === "switch") return executeSwitchNode(run, node, scopeKey);
  if (node.node_type === "random_split") return executeRandomSplitNode(run, node, scopeKey);
  if (node.node_type === "event_wait_multi") {
    const wait = await createMultiEventWait(run, node, scopeKey);
    await ctx.pool.query(`UPDATE automation_run_nodes SET status = 'waiting', output_snapshot = $2::jsonb, updated_at = now() WHERE id = $1`, [runNode.id, JSON.stringify({ wait_id: wait.id })]);
    await ctx.pool.query(`UPDATE automation_runs SET status = 'waiting', updated_at = now() WHERE id = $1`, [run.id]);
    await logRun(run, node, "info", "wait.multi_created", "Multi-event wait created", { wait_id: wait.id, scope_key: scopeKey });
    return { waiting: true };
  }
  if (node.node_type === "goal") return executeGoalNode(run, node, scopeKey);
  if (node.node_type === "stop") {
    await stopRun(run, "stop_node", resolveTemplate(node.config?.reason || "Stopped by automation node", await buildRunContext(run, { scopeKey })));
    return { stoppedRun: true, output: { stopped: true } };
  }
  if (node.node_type === "end") return { stoppedPath: true, output: { ended: true, reason: node.config?.reason || null } };
  if (node.node_type === "fail") {
    await failRun(run, "fail_node", resolveTemplate(node.config?.reason || "Failed by automation node", await buildRunContext(run, { scopeKey })));
    return { stoppedRun: true, output: { failed: true } };
  }
  if (node.node_type === "sub_automation") {
    return executeAutomationStart(run, node, node.config || {});
  }
  if (node.node_type === "action") {
    const actionKey = node.config?.action_key;
    const executor = actionExecutors[actionKey];
    if (!executor) throw new Error(`unknown_action:${actionKey}`);
    if (run.dry_run && !SIDE_EFFECT_FREE_ACTIONS.has(actionKey)) {
      const context = await buildRunContext(run, { scopeKey });
      const resolved = resolveConfig(node.config || {}, context);
      await logRun(run, node, "info", "action.dry_run", `Would execute ${actionKey}`, { resolved_config: redact(resolved) });
      return { port: "default", output: { would_execute: actionKey, resolved_config: redact(resolved) } };
    }
    await logRun(run, node, "info", "action.started", `Action started ${actionKey}`, {});
    const output = await executor(run, node, node.config || {}, scopeKey);
    if (output?.waiting) {
      await ctx.pool.query(`UPDATE automation_run_nodes SET status = 'waiting', output_snapshot = $2::jsonb, updated_at = now() WHERE id = $1`, [runNode.id, JSON.stringify(output)]);
      return output;
    }
    await logRun(run, node, "info", "action.completed", `Action completed ${actionKey}`, {});
    return { port: "default", output };
  }
  return { port: "default", output: {} };
}

async function traverse(run, graph, node, port, scopeKey = "root") {
  const edges = (graph.edgesBySource[node.id] || []).filter((edge) => portMatches(edge.source_port, port)).sort(edgeSort);
  if (!edges.length) return;
  for (const edge of edges) {
    await executeFromNode(run.id, edge.target_node_id, scopeKey, { source_node_id: node.id, source_port: port, edge_id: edge.id });
  }
}

async function executeForeachNode(run, node, scopeKey) {
  const graph = await loadGraph(run.automation_version_id, run.company_id);
  const context = await buildRunContext(run, { scopeKey });
  const maxItems = Math.min(Math.max(0, Number(node.config?.max_items || AUTOMATION_LIMITS.foreachDefaultMaxItems)), AUTOMATION_LIMITS.foreachHardMaxItems);
  const items = resolveCollection(node.config?.collection, context, { maxItems });
  if (items.length > maxItems) throw new Error("foreach_item_limit_exceeded");
  const budgeted = await ctx.pool.query(
    `UPDATE automation_runs SET total_iteration_count = total_iteration_count + $2, updated_at = now()
      WHERE id = $1 AND total_iteration_count + $2 <= $3
      RETURNING total_iteration_count`,
    [run.id, items.length, AUTOMATION_SAFETY_DEFAULTS.maxTotalIterationsPerRun]
  );
  if (!budgeted.rowCount) throw new AutomationError("budget_exceeded", "Nested foreach iteration budget exceeded", { retryable: false });
  const mode = node.config?.execution_mode || "sequential";
  const failurePolicy = node.config?.failure_policy || "stop_all";
  const iterationRows = [];
  for (let index = 0; index < items.length; index++) {
    const iterationKey = String(index);
    const childScope = `${scopeKey}/foreach:${node.id}:item:${index}`;
    if (childScope.split("/").length - 1 > AUTOMATION_LIMITS.maxScopeDepth) throw new Error("foreach_scope_depth_exceeded");
    const row = (await ctx.pool.query(
      `INSERT INTO automation_run_iterations(run_id, foreach_node_id, foreach_node_key, parent_scope_key, scope_key, iteration_key, item_index, item_count, item_data, status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'queued')
       ON CONFLICT(run_id, foreach_node_id, parent_scope_key, iteration_key)
       DO UPDATE SET item_count = EXCLUDED.item_count, item_data = EXCLUDED.item_data, updated_at = now()
       RETURNING *`,
      [run.id, node.id, node.node_key, scopeKey, childScope, iterationKey, index, items.length, JSON.stringify(items[index])]
    )).rows[0];
    iterationRows.push(row);
  }
  const queued = iterationRows.filter((row) => !["completed", "failed"].includes(row.status));
  const runOne = async (iteration) => {
    await ctx.pool.query(`UPDATE automation_run_iterations SET status = 'running', started_at = COALESCE(started_at, now()), updated_at = now() WHERE id = $1 AND status IN ('queued','running')`, [iteration.id]);
    try {
      await traverse(run, graph, node, "item", iteration.scope_key);
      const activeWait = await ctx.pool.query(`SELECT 1 FROM automation_waits WHERE run_id = $1 AND scope_key = $2 AND status = 'waiting' LIMIT 1`, [run.id, iteration.scope_key]);
      if (activeWait.rowCount) {
        await ctx.pool.query(`UPDATE automation_run_iterations SET status = 'waiting', updated_at = now() WHERE id = $1`, [iteration.id]);
        return;
      }
      await ctx.pool.query(`UPDATE automation_run_iterations SET status = 'completed', completed_at = COALESCE(completed_at, now()), updated_at = now() WHERE id = $1`, [iteration.id]);
    } catch (e) {
      await ctx.pool.query(`UPDATE automation_run_iterations SET status = 'failed', error = $2, failed_at = now(), updated_at = now() WHERE id = $1`, [iteration.id, (e?.message || "iteration_failed").slice(0, 1000)]);
      if (failurePolicy === "stop_all") throw e;
    }
  };
  if (mode === "parallel") {
    const parallelism = Math.min(Math.max(1, Number(node.config?.parallelism || 3)), AUTOMATION_LIMITS.foreachMaxParallelism);
    for (let i = 0; i < queued.length; i += parallelism) await Promise.all(queued.slice(i, i + parallelism).map(runOne));
  } else {
    for (const iteration of queued) await runOne(iteration);
  }
  const summary = await foreachSummary(run.id, node.id, scopeKey);
  if (summary.waiting_count > 0) {
    await ctx.pool.query(`UPDATE automation_runs SET status = 'waiting', updated_at = now() WHERE id = $1`, [run.id]);
    return { waiting: true, output: summary };
  }
  if (summary.failed_count > 0 && failurePolicy === "stop_all") throw new Error("foreach_iteration_failed");
  await traverse(run, graph, node, "done", scopeKey);
  return { stoppedPath: true, output: summary };
}

async function foreachSummary(runId, nodeId, parentScopeKey) {
  const rows = (await ctx.pool.query(
    `SELECT status, item_index, item_data, error FROM automation_run_iterations WHERE run_id = $1 AND foreach_node_id = $2 AND parent_scope_key = $3 ORDER BY item_index ASC`,
    [runId, nodeId, parentScopeKey]
  )).rows;
  const successful = rows.filter((r) => r.status === "completed");
  const failed = rows.filter((r) => r.status === "failed");
  const waiting = rows.filter((r) => r.status === "waiting" || r.status === "running");
  return {
    total_count: rows.length,
    successful_count: successful.length,
    failed_count: failed.length,
    waiting_count: waiting.length,
    items: capCollection(rows.map((r) => ({ index: r.item_index, status: r.status, item: r.item_data, error: r.error })), 100),
    successful_items: capCollection(successful.map((r) => r.item_data), 100),
    failed_items: capCollection(failed.map((r) => ({ item: r.item_data, error: r.error })), 100)
  };
}

async function completeIterationScopeIfIdle(runId, scopeKey) {
  const waiting = await ctx.pool.query(`SELECT 1 FROM automation_waits WHERE run_id = $1 AND scope_key = $2 AND status = 'waiting' LIMIT 1`, [runId, scopeKey]);
  if (waiting.rowCount) return;
  const iteration = (await ctx.pool.query(`UPDATE automation_run_iterations SET status = 'completed', completed_at = COALESCE(completed_at, now()), updated_at = now() WHERE run_id = $1 AND scope_key = $2 AND status IN ('queued','running','waiting') RETURNING *`, [runId, scopeKey])).rows[0];
  if (!iteration) return;
  const remaining = await ctx.pool.query(
    `SELECT 1 FROM automation_run_iterations
      WHERE run_id = $1 AND foreach_node_id = $2 AND parent_scope_key = $3 AND status NOT IN ('completed','failed')
      LIMIT 1`,
    [runId, iteration.foreach_node_id, iteration.parent_scope_key]
  );
  if (remaining.rowCount) return;
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [runId])).rows[0];
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  const node = (await ctx.pool.query(`SELECT * FROM automation_nodes WHERE id = $1`, [iteration.foreach_node_id])).rows[0];
  if (!node) return;
  const failurePolicy = node.config?.failure_policy || "stop_all";
  const summary = await foreachSummary(runId, iteration.foreach_node_id, iteration.parent_scope_key);
  if (summary.failed_count > 0 && failurePolicy === "stop_all") return failRun(run, "foreach_iteration_failed", "A foreach iteration failed");
  const graph = await loadGraph(run.automation_version_id, run.company_id);
  await traverse(run, graph, node, "done", iteration.parent_scope_key);
  if (iteration.parent_scope_key === "root") await completeRunIfIdle(run);
}

async function executeMergeNode(run, node, scopeKey, arrival) {
  const arrivalKey = arrival?.edge_id || `${arrival?.source_node_id || "unknown"}:${arrival?.source_port || "default"}`;
  await ctx.pool.query(
    `INSERT INTO automation_merge_arrivals(run_id, merge_node_id, scope_key, arrival_key, source_node_id, source_port)
     VALUES($1,$2,$3,$4,$5,$6)
     ON CONFLICT(run_id, merge_node_id, scope_key, arrival_key) DO NOTHING`,
    [run.id, node.id, scopeKey, arrivalKey, arrival?.source_node_id || null, arrival?.source_port || null]
  );
  const mode = String(node.config?.mode || "any").toLowerCase();
  const graph = await loadGraph(run.automation_version_id, run.company_id);
  const inbound = graph.edges.filter((e) => e.target_node_id === node.id);
  const arrived = (await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM automation_merge_arrivals WHERE run_id = $1 AND merge_node_id = $2 AND scope_key = $3`, [run.id, node.id, scopeKey])).rows[0].count;
  const alreadyReleased = await ctx.pool.query(`SELECT 1 FROM automation_merge_arrivals WHERE run_id = $1 AND merge_node_id = $2 AND scope_key = $3 AND released_at IS NOT NULL LIMIT 1`, [run.id, node.id, scopeKey]);
  if (alreadyReleased.rowCount) return { stoppedPath: true, output: { mode, arrived, released: false } };
  const shouldRelease = mode === "all" ? Number(arrived) >= inbound.length : true;
  if (!shouldRelease) return { waiting: true, output: { mode, arrived, required: inbound.length } };
  const released = await ctx.pool.query(
    `UPDATE automation_merge_arrivals SET released_at = now()
      WHERE id = (
        SELECT id FROM automation_merge_arrivals WHERE run_id = $1 AND merge_node_id = $2 AND scope_key = $3 AND released_at IS NULL ORDER BY arrived_at ASC LIMIT 1
      )
      RETURNING id`,
    [run.id, node.id, scopeKey]
  );
  if (!released.rowCount) return { stoppedPath: true, output: { mode, arrived, released: false } };
  return { port: "default", output: { mode, arrived, required: inbound.length, released: true } };
}

function executeParallelNode(_run, node) {
  const ports = normalizeDynamicPorts(node.config).map((p) => p.id);
  return { ports, output: { ports } };
}

async function executeSwitchNode(run, node, scopeKey) {
  const context = await buildRunContext(run, { scopeKey });
  const input = resolveRawValue(node.config?.input, context);
  const cases = Array.isArray(node.config?.cases) ? node.config.cases : [];
  for (const item of cases) {
    const operator = item.operator || "equals";
    const condition = { operator, left: String(input ?? ""), value: item.value };
    if (evaluateCondition(condition, { value: input })) {
      const port = stablePortId(item.port || item.id || item.label || item.value);
      return { port, output: { input, port, matched: item.label || item.value } };
    }
  }
  return { port: "default", output: { input, port: "default" } };
}

async function executeRandomSplitNode(run, node, scopeKey) {
  const name = `random_split:${node.id}:${scopeKey}`;
  const existing = (await ctx.pool.query(`SELECT value FROM automation_variables WHERE run_id = $1 AND name = $2`, [run.id, name])).rows[0]?.value;
  if (existing?.port) return { port: existing.port, output: existing };
  const paths = normalizeDynamicPorts(node.config).filter((p) => p.weight > 0);
  const total = paths.reduce((sum, p) => sum + p.weight, 0);
  if (paths.length < 2 || Math.round(total) !== 100) throw new Error("random_split_weights_invalid");
  const seed = node.config?.mode === "sticky_subject" ? `${run.automation_version_id}:${run.subject_type}:${run.subject_id}:${node.id}` : `${run.id}:${node.id}:${scopeKey}`;
  const roll = hashNumber(seed) * 100;
  let cursor = 0;
  let selected = paths[paths.length - 1];
  for (const path of paths) {
    cursor += path.weight;
    if (roll <= cursor) { selected = path; break; }
  }
  const output = { port: selected.id, label: selected.label, weight: selected.weight, mode: node.config?.mode || "per_run" };
  await ctx.pool.query(
    `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
     ON CONFLICT(run_id, name) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [run.id, name, JSON.stringify(output)]
  );
  return { port: selected.id, output };
}

async function createMultiEventWait(run, node, scopeKey) {
  const context = await buildRunContext(run, { scopeKey });
  const events = (Array.isArray(node.config?.events) ? node.config.events : []).map((event, index) => ({
    event_type: event.event_type || event.type || event.key,
    port: stablePortId(event.port || event.label || event.event_type || `event_${index + 1}`),
    filter: event.filter || event.match || {}
  })).filter((event) => event.event_type);
  if (!events.length) throw new Error("multi_wait_events_required");
  const timeoutMs = node.config?.timeout ? parseDurationMs(resolveTemplate(node.config.timeout, context)) : null;
  return createWait(run, node, "event", {
    event_type: "*",
    event_filter: { events },
    timeout_at: timeoutMs ? new Date(Date.now() + timeoutMs).toISOString() : null,
    scope_key: scopeKey
  });
}

async function executeGoalNode(run, node, scopeKey) {
  const context = await buildRunContext(run, { scopeKey });
  const goalKey = stablePortId(resolveTemplate(node.config?.goal_key || node.title || node.node_key, context));
  const metadata = resolveConfig(node.config?.metadata || {}, context);
  await ctx.pool.query(
    `INSERT INTO automation_run_goals(run_id, node_id, goal_key, metadata, scope_key)
     VALUES($1,$2,$3,$4::jsonb,$5)
     ON CONFLICT(run_id, node_id, scope_key, goal_key) DO NOTHING`,
    [run.id, node.id, goalKey, JSON.stringify(safeJsonLimited(metadata)), scopeKey]
  );
  await logRun(run, node, "info", "goal.reached", `Goal reached: ${goalKey}`, { goal_key: goalKey, scope_key: scopeKey });
  return { port: "default", output: { goal_key: goalKey, metadata } };
}

function portMatches(edgePort, resultPort) {
  if (!edgePort) return resultPort === "default" || !resultPort;
  return edgePort === resultPort;
}

function edgeSort(a, b) {
  return (a.priority || 0) - (b.priority || 0);
}

async function completeRunIfIdle(run) {
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  const waiting = await ctx.pool.query(`SELECT 1 FROM automation_waits WHERE run_id = $1 AND status = 'waiting' LIMIT 1`, [run.id]);
  if (waiting.rowCount) {
    await ctx.pool.query(`UPDATE automation_runs SET status = 'waiting', updated_at = now() WHERE id = $1`, [run.id]);
    return;
  }
  await ctx.pool.query(`UPDATE automation_runs SET status = 'completed', completed_at = COALESCE(completed_at, now()), updated_at = now() WHERE id = $1 AND status NOT IN ('failed','canceled','stopped')`, [run.id]);
  await logRun(run, null, "info", "run.completed", "Run completed", {});
}

async function failRun(run, code, message) {
  await ctx.pool.query(
    `UPDATE automation_runs SET status = 'failed', completed_at = COALESCE(completed_at, now()), error_code = $2, error_message = $3, updated_at = now()
      WHERE id = $1`,
    [run.id, code, message]
  );
  await logRun(run, null, "error", "run.failed", message, { code });
  await maybeAutoPauseAutomation(run, code, message);
}

async function stopRun(run, code, message, stopConditionKey = null) {
  await ctx.pool.query(
    `UPDATE automation_runs SET status = 'stopped', completed_at = COALESCE(completed_at, now()), error_code = $2, error_message = $3, stop_reason = $3, stop_condition_key = $4, updated_at = now()
      WHERE id = $1`,
    [run.id, code, message, stopConditionKey]
  );
  await cancelRunContinuations(run.id);
  await logRun(run, null, "info", "run.stopped", message, { code, stop_condition_key: stopConditionKey });
}

async function cancelAutomationRun(runId, companyId, code = "run_canceled", message = "Run canceled", metadata = {}) {
  const { rows } = await ctx.pool.query(
    `UPDATE automation_runs SET status = 'canceled', completed_at = now(), error_code = $3, error_message = $4, updated_at = now()
      WHERE id = $1 AND company_id = $2 AND status IN ('queued','running','waiting','paused')
      RETURNING *`,
    [runId, companyId, code, message]
  );
  if (!rows.length) return { run: null };
  const counts = await cancelRunContinuations(runId);
  await logRun(rows[0], null, "info", "run.canceled", message, metadata);
  return { run: rows[0], ...counts };
}

async function cancelRunContinuations(runId) {
  const waits = await ctx.pool.query(`UPDATE automation_waits SET status = 'canceled', updated_at = now() WHERE run_id = $1 AND status = 'waiting' RETURNING id`, [runId]);
  const iterations = await ctx.pool.query(`UPDATE automation_run_iterations SET status = 'canceled', updated_at = now() WHERE run_id = $1 AND status IN ('queued','running','waiting') RETURNING id`, [runId]);
  const nodes = await ctx.pool.query(`UPDATE automation_run_nodes SET status = 'canceled', updated_at = now() WHERE run_id = $1 AND status IN ('queued','running','waiting_retry','waiting') RETURNING id`, [runId]);
  await ctx.pool.query(`UPDATE automation_run_monitors SET status = 'canceled', updated_at = now() WHERE run_id = $1 AND status = 'active'`, [runId]);
  return { canceled_waits: waits.rowCount, canceled_iterations: iterations.rowCount, canceled_nodes: nodes.rowCount };
}

async function emergencyStopCompanyAutomations(companyId, userId) {
  await ctx.pool.query(`UPDATE companies SET automations_enabled = false, automation_emergency_stopped_at = now(), updated_at = now() WHERE id = $1`, [companyId]);
  const active = (await ctx.pool.query(`SELECT id FROM automation_runs WHERE company_id = $1 AND status IN ('queued','running','waiting','paused')`, [companyId])).rows;
  let canceled = 0;
  for (const row of active) {
    const result = await cancelAutomationRun(row.id, companyId, "emergency_stop", "Company emergency automation stop", { user_id: userId });
    if (result.run) canceled += 1;
  }
  await ctx.pool.query(`UPDATE automation_definitions SET status = 'paused', updated_at = now() WHERE company_id = $1 AND status = 'published'`, [companyId]);
  return { ok: true, canceled_runs: canceled };
}

async function shouldStopRun(run) {
  const version = (await ctx.pool.query(`SELECT settings FROM automation_versions WHERE id = $1`, [run.automation_version_id])).rows[0];
  const stop = version?.settings?.stop_condition;
  if (!stop) return false;
  const context = await buildRunContext(run);
  return evaluateCondition(stop, context);
}

async function createWaitForNode(run, node, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const mode = node.config?.mode || node.config?.wait_type || "duration";
  if (mode === "duration") {
    const resumeAt = new Date(Date.now() + parseDurationMs(resolveTemplate(node.config?.duration || node.config?.value || "1 minute", context)));
    return createWait(run, node, "duration", { resume_at: resumeAt.toISOString(), scope_key: scopeKey });
  }
  if (mode === "business_days") {
    const days = Math.max(1, Number(resolveTemplate(node.config?.amount || node.config?.days || 1, context)) || 1);
    const resumeAt = addBusinessDays(new Date(), days, context.company || {});
    return createWait(run, node, "duration", { resume_at: resumeAt.toISOString(), scope_key: scopeKey });
  }
  if (mode === "next_business_open") {
    return createWait(run, node, "duration", { resume_at: nextBusinessOpen(new Date(), context.company || {}).toISOString(), scope_key: scopeKey });
  }
  if (mode === "random_duration") {
    const minMs = parseDurationMs(resolveTemplate(node.config?.min_duration || "1 minute", context));
    const maxMs = Math.max(minMs, parseDurationMs(resolveTemplate(node.config?.max_duration || "5 minutes", context)));
    const key = `wait_random:${node.id}:${scopeKey}`;
    const existing = (await ctx.pool.query(`SELECT value FROM automation_variables WHERE run_id = $1 AND name = $2`, [run.id, key])).rows[0]?.value;
    const chosenMs = Number(existing?.chosen_ms || 0) || Math.round(minMs + hashNumber(`${run.id}:${node.id}:${scopeKey}`) * (maxMs - minMs));
    if (!existing) {
      await ctx.pool.query(
        `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
         ON CONFLICT(run_id, name) DO NOTHING`,
        [run.id, key, JSON.stringify({ chosen_ms: chosenMs })]
      );
    }
    return createWait(run, node, "duration", { resume_at: new Date(Date.now() + chosenMs).toISOString(), scope_key: scopeKey });
  }
  if (mode === "until_datetime") {
    let date = null;
    if (node.config?.relative_basis) {
      date = resolveDateExpression({
        basis: node.config.relative_basis,
        direction: node.config.relative_direction || "before",
        amount: Number(node.config.relative_amount || 0),
        unit: node.config.relative_unit || "hours"
      }, context);
    } else {
      const value = resolveTemplate(node.config?.until || node.config?.datetime || "", context);
      date = new Date(value);
    }
    if (!date || Number.isNaN(date.getTime())) throw new Error("invalid_wait_datetime");
    return createWait(run, node, "until_datetime", { resume_at: date.toISOString(), scope_key: scopeKey });
  }
  if (mode === "event_wait") {
    const timeoutMs = node.config?.timeout ? parseDurationMs(resolveTemplate(node.config.timeout, context)) : null;
    return createWait(run, node, "event", {
      event_type: node.config?.event_type,
      event_filter: node.config?.event_filter || null,
      timeout_at: timeoutMs ? new Date(Date.now() + timeoutMs).toISOString() : null,
      scope_key: scopeKey
    });
  }
  throw new Error("unknown_wait_mode");
}

async function createWait(run, node, waitType, values) {
  const eventFilter = values.retry ? { ...(values.event_filter || {}), retry: true } : values.event_filter;
  const { rows } = await ctx.pool.query(
    `INSERT INTO automation_waits(run_id, node_id, wait_type, resume_at, event_type, event_filter, timeout_at, status, scope_key, resume_port)
     VALUES($1,$2,$3,$4::timestamptz,$5,$6::jsonb,$7::timestamptz,'waiting',$8,$9) RETURNING *`,
    [run.id, node.id, waitType, values.resume_at || null, values.event_type || null, eventFilter ? JSON.stringify(eventFilter) : null, values.timeout_at || null, values.scope_key || "root", values.resume_port || null]
  );
  return rows[0];
}

function parseDurationMs(value) {
  if (typeof value === "number") return Math.max(0, value * 1000);
  const s = (value || "").toString().trim().toLowerCase();
  const match = s.match(/^(\d+(?:\.\d+)?)\s*(second|seconds|sec|secs|minute|minutes|min|mins|hour|hours|day|days|week|weeks)$/);
  if (!match) return 60 * 1000;
  const n = Number(match[1]);
  const unit = match[2];
  const scale = unit.startsWith("sec") ? 1000 : unit.startsWith("min") ? 60000 : unit.startsWith("hour") ? 3600000 : unit.startsWith("day") ? 86400000 : 604800000;
  return Math.max(0, n * scale);
}

async function processDueWaits() {
  const db = await ctx.pool.connect();
  let waits = [];
  try {
    await db.query("BEGIN");
    waits = (await db.query(
      `SELECT * FROM automation_waits
        WHERE status = 'waiting'
          AND ((resume_at IS NOT NULL AND resume_at <= now()) OR (timeout_at IS NOT NULL AND timeout_at <= now()))
        ORDER BY COALESCE(resume_at, timeout_at) ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED`,
      [AUTOMATION_LIMITS.waitBatchSize]
    )).rows;
    await db.query(`UPDATE automation_waits SET status = CASE WHEN timeout_at IS NOT NULL AND timeout_at <= now() THEN 'timed_out' ELSE 'ready' END, updated_at = now() WHERE id = ANY($1::uuid[])`, [waits.map((w) => w.id)]);
    await db.query("COMMIT");
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    console.error("[automations] due waits failed", e?.message || e);
  } finally {
    db.release();
  }
  for (const wait of waits) await resumeWait(wait, wait.timeout_at && new Date(wait.timeout_at) <= new Date() ? "timeout" : "default");
}

async function wakeEventWaits(event) {
  const { rows } = await ctx.pool.query(
    `SELECT w.*
       FROM automation_waits w
       JOIN automation_runs r ON r.id = w.run_id
      WHERE w.status = 'waiting'
        AND w.wait_type = 'event'
        AND r.company_id = $1
        AND (w.event_type = $2 OR w.event_type = '*')`,
    [event.company_id, event.event_type]
  );
  for (const wait of rows) {
    const match = eventWaitMatch(wait, event);
    if (!match.matched) continue;
    const claimed = (await ctx.pool.query(
      `UPDATE automation_waits
          SET status = 'ready', resume_port = $2, matched_event = $3::jsonb, updated_at = now()
        WHERE id = $1 AND status = 'waiting'
        RETURNING *`,
      [wait.id, match.port || "event", JSON.stringify({ event_id: event.id, event_type: event.event_type, payload: safeJson(event.payload || {}), matched_at: new Date().toISOString() })]
    )).rows[0];
    if (claimed) await resumeWait(claimed, claimed.resume_port || "event");
  }
}

function eventWaitMatch(wait, event) {
  const filter = wait.event_filter || {};
  const candidates = Array.isArray(filter.events) && filter.events.length
    ? filter.events
    : [{ event_type: wait.event_type, port: "event", filter }];
  for (const candidate of candidates) {
    const eventType = candidate.event_type || candidate.type || candidate.key;
    if (eventType && eventType !== event.event_type) continue;
    const matchFilter = candidate.filter || candidate.match || candidate;
    if (!singleEventFilterMatches(matchFilter, event, wait)) continue;
    return { matched: true, port: candidate.port || candidate.output_port || stablePortId(candidate.label || eventType || "event") };
  }
  return { matched: false };
}

function singleEventFilterMatches(filter, event, wait) {
  const payload = event.payload || {};
  if (!filter) return true;
  if (filter.subject_id && String(filter.subject_id) !== String(event.subject_id || "")) return false;
  if (filter.subject_type && String(filter.subject_type) !== String(event.subject_type || "")) return false;
  if (filter.contact_id && String(filter.contact_id) !== String(payload.contact_id || "")) return false;
  if (filter.conversation_id && String(filter.conversation_id) !== String(payload.conversation_id || "")) return false;
  if (filter.payment_id && String(filter.payment_id) !== String(payload.payment_id || payload.id || "")) return false;
  if (filter.quote_id && String(filter.quote_id) !== String(payload.quote_id || payload.id || "")) return false;
  if (filter.route_id && String(filter.route_id) !== String(payload.route_id || payload.id || "")) return false;
  if (filter.service_plan_id && String(filter.service_plan_id) !== String(payload.service_plan_id || payload.id || "")) return false;
  if (filter.same_subject === true) {
    if (String(event.subject_type || "") !== String(wait.subject_type || event.subject_type || "")) return false;
  }
  return true;
}

async function resumeWait(wait, port) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [wait.run_id])).rows[0];
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  const resumePort = wait.resume_port || port;
  await ctx.pool.query(`UPDATE automation_waits SET status = CASE WHEN $2 = 'timeout' THEN 'timed_out' ELSE 'completed' END, updated_at = now() WHERE id = $1`, [wait.id, resumePort]);
  const node = (await ctx.pool.query(`SELECT * FROM automation_nodes WHERE id = $1`, [wait.node_id])).rows[0];
  if (node) await logRun(run, node, "info", "wait.resumed", `Wait resumed through ${resumePort}`, { wait_id: wait.id, scope_key: wait.scope_key || "root" });
  if (wait.event_filter?.retry === true) {
    await executeFromNode(run.id, wait.node_id, wait.scope_key || "root");
  } else {
    await runAutomation(run.id, wait.node_id, resumePort, wait.scope_key || "root");
  }
}

function startAutomationProcessors() {
  setInterval(() => processAutomationEvents().catch((e) => console.error("[automations] processor failed", e?.message || e)), 5000).unref?.();
  setInterval(() => processDueWaits().catch((e) => console.error("[automations] wait processor failed", e?.message || e)), 5000).unref?.();
  setInterval(() => processScheduledAutomationEvents().catch((e) => console.error("[automations] scheduled event processor failed", e?.message || e)), 30000).unref?.();
  setInterval(() => ctx.pool.query(`UPDATE automation_definitions SET status = 'published', pause_until = NULL WHERE status = 'paused' AND pause_until IS NOT NULL AND pause_until <= now() AND active_version_id IS NOT NULL`).catch(() => {}), 60000).unref?.();
}

async function processScheduledAutomationEvents() {
  const db = await ctx.pool.connect();
  let rows = [];
  try {
    await db.query("BEGIN");
    rows = (await db.query(
      `UPDATE automation_scheduled_events
          SET status = 'firing', locked_at = now(), locked_by = $1, attempt_count = attempt_count + 1, updated_at = now()
        WHERE id IN (
          SELECT id FROM automation_scheduled_events
           WHERE status IN ('scheduled','failed')
             AND scheduled_for <= now()
             AND (next_attempt_at IS NULL OR next_attempt_at <= now())
             AND (locked_at IS NULL OR locked_at < now() - interval '120 seconds')
           ORDER BY scheduled_for ASC
           LIMIT 50
           FOR UPDATE SKIP LOCKED
        )
        RETURNING *`,
      [workerId()]
    )).rows;
    await db.query("COMMIT");
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    db.release();
  }
  for (const row of rows) {
    try {
      if (!(await shouldFireScheduledAutomationEvent(row))) {
        await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'canceled', locked_at = NULL, locked_by = NULL, updated_at = now() WHERE id = $1`, [row.id]);
        continue;
      }
      const eventId = await emitAutomationEvent({
        companyId: row.company_id,
        eventType: row.event_type,
        subjectType: row.subject_type,
        subjectId: row.subject_id,
        source: row.source,
        dedupeKey: row.schedule_key,
        payload: row.payload || {},
        occurredAt: row.scheduled_for
      });
      await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'fired', fired_at = now(), locked_at = NULL, locked_by = NULL, updated_at = now() WHERE id = $1`, [row.id]);
      if (!eventId) console.warn("[automations] scheduled event emitted no id", { scheduleKey: row.schedule_key });
    } catch (e) {
      const attempts = Number(row.attempt_count || 0);
      if (attempts >= AUTOMATION_SAFETY_DEFAULTS.eventMaxAttempts) {
        await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'dead_letter', error = $2, locked_at = NULL, locked_by = NULL, updated_at = now() WHERE id = $1`, [row.id, (e?.message || "scheduled_event_failed").slice(0, 1000)]);
        await createDeadLetter({ companyId: row.company_id, sourceType: "scheduled_event", sourceId: row.id, eventType: row.event_type, subjectType: row.subject_type, subjectId: row.subject_id, attempts, errorCode: "scheduled_event_failed", errorMessage: e?.message || "Scheduled event failed" });
      } else {
        const delay = Math.min(300, 5 * Math.pow(2, attempts - 1));
        await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'failed', error = $2, next_attempt_at = now() + ($3::int * interval '1 second'), locked_at = NULL, locked_by = NULL, updated_at = now() WHERE id = $1`, [row.id, (e?.message || "scheduled_event_failed").slice(0, 1000), delay]);
      }
    }
  }
}

async function shouldFireScheduledAutomationEvent(row) {
  if (row.subject_type === "job") {
    const job = (await ctx.pool.query(`SELECT finished_at FROM schedule_events WHERE id = $1 AND company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!job) return false;
    if (row.event_type === "job.overdue" && job.finished_at) return false;
  }
  if (row.subject_type === "task") {
    const task = (await ctx.pool.query(`SELECT completed FROM todo_tasks tt JOIN users u ON u.id = tt.user_id WHERE tt.id = $1 AND u.company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!task) return false;
    if (row.event_type === "task.overdue" && task.completed) return false;
  }
  if (row.subject_type === "customer_reminder") {
    const reminder = (await ctx.pool.query(`SELECT completed FROM todo_customer_reminders cr JOIN users u ON u.id = cr.user_id WHERE cr.id = $1 AND u.company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!reminder) return false;
    if (row.event_type === "customer_reminder.overdue" && reminder.completed) return false;
  }
  if (row.subject_type === "routine" && row.event_type === "routine.missed") {
    const dayKey = row.payload?.occurrence_date;
    const done = await ctx.pool.query(`SELECT 1 FROM todo_routine_done rd JOIN users u ON u.id = rd.user_id WHERE rd.routine_id = $1 AND rd.day_key = $2 AND u.company_id = $3 LIMIT 1`, [row.subject_id, dayKey, row.company_id]);
    if (done.rowCount) return false;
  }
  if (row.event_type === "sms.no_reply") {
    const inbound = await ctx.pool.query(
      `SELECT 1 FROM sms_messages WHERE conversation_id = $1 AND direction = 'inbound' AND created_at > (SELECT created_at FROM sms_messages WHERE id = $2) AND deleted_at IS NULL LIMIT 1`,
      [row.subject_id, row.payload?.message_id]
    );
    if (inbound.rowCount) return false;
  }
  if (row.event_type === "sms.conversation_inactive") {
    const latest = await ctx.pool.query(`SELECT id FROM sms_messages WHERE conversation_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1`, [row.subject_id]);
    if (latest.rows[0]?.id && row.payload?.last_message_id && latest.rows[0].id !== row.payload.last_message_id) return false;
  }
  if (row.event_type === "voicemail.unread_for") {
    const vm = (await ctx.pool.query(`SELECT is_read, deleted_at FROM voicemails WHERE id = $1 AND company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!vm || vm.is_read || vm.deleted_at) return false;
  }
  if (row.subject_type === "quote") {
    const quote = (await ctx.pool.query(`SELECT status, expires_at, sent_at, updated_at FROM quotes WHERE id::text = $1 AND company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!quote || ["accepted", "declined", "converted", "deleted"].includes(String(quote.status || ""))) return false;
    if (row.event_type === "quote.expired" && (!quote.expires_at || new Date(quote.expires_at) > new Date())) return false;
  }
  if (row.subject_type === "invoice") {
    const invoice = (await ctx.pool.query(`SELECT status, due_at, total_cents FROM invoices WHERE id::text = $1 AND company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!invoice || ["paid", "void", "deleted"].includes(String(invoice.status || ""))) return false;
    if (row.event_type === "invoice.overdue" && (!invoice.due_at || new Date(invoice.due_at) > new Date())) return false;
  }
  if (row.subject_type === "service_plan") {
    const plan = (await ctx.pool.query(`SELECT status, next_service_date FROM service_plans WHERE id::text = $1 AND company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!plan || !["active", "payment_pending", "past_due"].includes(String(plan.status || ""))) return false;
    if (!plan.next_service_date || row.payload?.next_service_date !== new Date(plan.next_service_date).toISOString().slice(0, 10)) return false;
  }
  if (row.subject_type === "map_pin") {
    const pin = (await ctx.pool.query(`SELECT status, contact_id, last_knock_at, last_visit_at FROM map_pins p JOIN users u ON u.id = p.user_id WHERE p.id = $1 AND u.company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!pin || ["won", "lost"].includes(String(pin.status || ""))) return false;
    if (Array.isArray(row.payload?.statuses) && row.payload.statuses.length && !row.payload.statuses.includes(pin.status)) return false;
  }
  if (row.subject_type === "time_entry") {
    const entry = (await ctx.pool.query(`SELECT user_id, end_at FROM time_clock_entries WHERE id = $1 AND company_id = $2`, [row.subject_id, row.company_id])).rows[0];
    if (!entry || entry.end_at) return false;
  }
  return true;
}

async function buildRunContext(run, options = {}) {
  const scopeKey = options.scopeKey || "root";
  const event = run.trigger_event_id ? (await ctx.pool.query(`SELECT * FROM automation_events WHERE id = $1`, [run.trigger_event_id])).rows[0] : null;
  const company = (await ctx.pool.query(`SELECT id, name, website, address, phone, email, timezone, business_days, business_open_time, business_close_time FROM companies WHERE id = $1`, [run.company_id])).rows[0] || {};
  const now = new Date();
  const variables = Object.fromEntries((await ctx.pool.query(`SELECT name, value FROM automation_variables WHERE run_id = $1`, [run.id])).rows.map((r) => [r.name, r.value]));
  const nodeRows = options.slim ? [] : (await ctx.pool.query(`SELECT node_key, output_snapshot, scope_key FROM automation_run_nodes WHERE run_id = $1 AND scope_key IN ('root', $2) ORDER BY created_at ASC`, [run.id, scopeKey])).rows;
  const nodes = {};
  for (const row of nodeRows) nodes[row.node_key] = { output: row.output_snapshot || {} };
  const iteration = scopeKey !== "root"
    ? (await ctx.pool.query(`SELECT * FROM automation_run_iterations WHERE run_id = $1 AND scope_key = $2 LIMIT 1`, [run.id, scopeKey])).rows[0]
    : null;
  const parentIteration = iteration?.parent_scope_key && iteration.parent_scope_key !== "root"
    ? (await ctx.pool.query(`SELECT * FROM automation_run_iterations WHERE run_id = $1 AND scope_key = $2 LIMIT 1`, [run.id, iteration.parent_scope_key])).rows[0]
    : null;
  const context = {
    company,
    event: event ? { id: event.id, type: event.event_type, payload: event.payload || {}, subject_type: event.subject_type, subject_id: event.subject_id } : {},
    variables,
    nodes,
    subject: { type: run.subject_type, id: run.subject_id },
    scope: { key: scopeKey },
    item: iteration?.item_data || null,
    item_index: iteration?.item_index ?? null,
    iteration: iteration ? {
      id: iteration.id,
      index: iteration.item_index,
      count: iteration.item_count,
      first: iteration.item_index === 0,
      last: iteration.item_index === Number(iteration.item_count || 0) - 1,
      item: iteration.item_data || null,
      parent: parentIteration ? {
        index: parentIteration.item_index,
        count: parentIteration.item_count,
        item: parentIteration.item_data || null
      } : null
    } : {},
    time: {
      now: now.toISOString(),
      hour: now.getUTCHours(),
      minute: now.getUTCMinutes(),
      day_of_week: now.getUTCDay() + 1,
      date: now.toISOString().slice(0, 10),
      is_weekday: now.getUTCDay() >= 1 && now.getUTCDay() <= 5,
      is_weekend: now.getUTCDay() === 0 || now.getUTCDay() === 6,
      is_business_hours: isWithinBusinessHours(now, company)
    }
  };
  if (!options.slim) {
    const subject = await loadSubject(run.company_id, run.subject_type, run.subject_id);
    if (run.subject_type) context[subjectContextKey(run.subject_type)] = subject || {};
    context.subject.object = subject || {};
    if (subject?.contact_id && !context.contact) context.contact = await loadContactContext(run.company_id, subject.contact_id);
    if (context.event?.payload?.contact_id && !context.contact) context.contact = await loadContactContext(run.company_id, context.event.payload.contact_id);
    if (context.contact?.id) {
      context.lead = leadContextFromContact(context.contact, context.event?.payload || {});
      context.pipeline = await loadPipelineContext(run.company_id, context.contact.id);
    }
  }
  return context;
}

function isWithinBusinessHours(date, company) {
  const days = Array.isArray(company.business_days) ? company.business_days.map(Number) : [1, 2, 3, 4, 5];
  const day = date.getUTCDay() || 7;
  if (!days.includes(day)) return false;
  const hhmm = `${String(date.getUTCHours()).padStart(2, "0")}:${String(date.getUTCMinutes()).padStart(2, "0")}`;
  return hhmm >= (company.business_open_time || "09:00") && hhmm <= (company.business_close_time || "17:00");
}

function addBusinessDays(date, count, company) {
  const days = Array.isArray(company.business_days) ? company.business_days.map(Number) : [1, 2, 3, 4, 5];
  const result = new Date(date);
  let remaining = Math.max(0, Number(count) || 0);
  while (remaining > 0) {
    result.setUTCDate(result.getUTCDate() + 1);
    const day = result.getUTCDay() || 7;
    if (days.includes(day)) remaining -= 1;
  }
  return nextBusinessOpen(result, company);
}

function nextBusinessOpen(date, company) {
  const days = Array.isArray(company.business_days) ? company.business_days.map(Number) : [1, 2, 3, 4, 5];
  const [openHour, openMinute] = String(company.business_open_time || "09:00").split(":").map(Number);
  const [closeHour, closeMinute] = String(company.business_close_time || "17:00").split(":").map(Number);
  const result = new Date(date);
  for (let i = 0; i < 14; i++) {
    const day = result.getUTCDay() || 7;
    const open = new Date(result);
    open.setUTCHours(openHour || 9, openMinute || 0, 0, 0);
    const close = new Date(result);
    close.setUTCHours(closeHour || 17, closeMinute || 0, 0, 0);
    if (days.includes(day) && result <= close) return result <= open ? open : result;
    result.setUTCDate(result.getUTCDate() + 1);
    result.setUTCHours(openHour || 9, openMinute || 0, 0, 0);
  }
  return result;
}

async function loadSubject(companyId, subjectType, subjectId) {
  if (!subjectType || !subjectId) return null;
  if (subjectType === "contact") return loadContactContext(companyId, subjectId);
  if (subjectType === "job") return loadJobContext(companyId, subjectId);
  if (subjectType === "opportunity") return (await ctx.pool.query(`SELECT * FROM opportunities WHERE id = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "sms_message") return loadSmsMessageContext(companyId, subjectId);
  if (subjectType === "sms_conversation") return loadSmsConversationContext(companyId, subjectId);
  if (subjectType === "call") return loadCallContext(companyId, subjectId);
  if (subjectType === "voicemail") return loadVoicemailContext(companyId, subjectId);
  if (subjectType === "internal_message") return loadInternalMessageContext(companyId, subjectId);
  if (subjectType === "internal_conversation") return loadInternalConversationContext(companyId, subjectId);
  if (subjectType === "channel") return loadChannelContext(companyId, subjectId);
  if (subjectType === "quote") return loadQuoteContext(companyId, subjectId);
  if (subjectType === "invoice") return loadInvoiceContext(companyId, subjectId);
  if (subjectType === "service_plan") return loadServicePlanContext(companyId, subjectId);
  if (subjectType === "task") return loadTaskContext(companyId, subjectId);
  if (subjectType === "routine") return loadRoutineContext(companyId, subjectId);
  if (subjectType === "customer_reminder") return loadCustomerReminderContext(companyId, subjectId);
  if (subjectType === "payment") return loadPaymentContext(companyId, subjectId);
  if (subjectType === "map_pin") return loadMapPinContext(companyId, subjectId);
  if (subjectType === "route") return loadRouteContext(companyId, subjectId);
  if (subjectType === "route_stop") return loadRouteStopContext(companyId, subjectId);
  if (subjectType === "employee") return loadEmployeeContext(companyId, subjectId);
  if (subjectType === "time_entry") return loadTimeEntryContext(companyId, subjectId);
  if (subjectType === "measurement") return loadMeasurementContext(companyId, subjectId);
  return null;
}

async function loadQuoteContext(companyId, quoteId) {
  const quote = (await ctx.pool.query(`SELECT * FROM quotes WHERE id::text = $1 AND company_id = $2`, [quoteId, companyId])).rows[0];
  if (!quote) return { exists: false };
  const items = Array.isArray(quote.line_items) ? quote.line_items : [];
  return { ...quote, exists: true, subtotal: quote.total_cents, total: quote.total_cents, subtotal_cents: quote.total_cents, line_item_count: items.length, is_expired: quote.expires_at ? new Date(quote.expires_at) <= new Date() : false, is_accepted: quote.status === "accepted", is_declined: quote.status === "declined", is_converted: quote.status === "converted" };
}

async function loadInvoiceContext(companyId, invoiceId) {
  const invoice = (await ctx.pool.query(`SELECT * FROM invoices WHERE id::text = $1 AND company_id = $2`, [invoiceId, companyId])).rows[0];
  if (!invoice) return { exists: false };
  return { ...invoice, exists: true, is_paid: invoice.status === "paid", is_overdue: invoice.due_at ? new Date(invoice.due_at) < new Date() && !["paid", "void", "deleted"].includes(invoice.status) : false };
}

async function loadPaymentContext(companyId, paymentId) {
  const payment = (await ctx.pool.query(`SELECT * FROM payment_records WHERE id::text = $1 AND company_id = $2`, [paymentId, companyId])).rows[0];
  if (!payment) return { exists: false };
  return { ...payment, exists: true, amount: payment.amount_cents, is_paid: ["succeeded", "paid"].includes(payment.status), is_failed: payment.status === "failed", is_refunded: String(payment.status || "").includes("refunded") };
}

async function loadServicePlanContext(companyId, planId) {
  const plan = (await ctx.pool.query(`SELECT * FROM service_plans WHERE id::text = $1 AND company_id = $2`, [planId, companyId])).rows[0];
  if (!plan) return { exists: false };
  const serviceCount = (await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM service_plan_events WHERE service_plan_id = $1 AND event_type = 'serviced'`, [plan.id])).rows[0]?.count || 0;
  const next = plan.next_service_date ? new Date(plan.next_service_date) : null;
  const daysUntil = next && !Number.isNaN(next.getTime()) ? Math.ceil((next.getTime() - Date.now()) / 86400000) : null;
  return { ...plan, exists: true, price: plan.price_cents, active: plan.status === "active", paused: plan.status === "paused", canceled: plan.status === "canceled", last_serviced_at: plan.last_service_date, service_count: serviceCount, days_until_next_service: daysUntil, is_due: daysUntil != null && daysUntil <= 0, is_overdue: daysUntil != null && daysUntil < 0, subscription_status: plan.stripe_subscription_status };
}

async function loadMapPinContext(companyId, pinId) {
  const pin = (await ctx.pool.query(
    `SELECT p.*, ml.name AS list_name
       FROM map_pins p
       JOIN users u ON u.id = p.user_id
       LEFT JOIN map_lists ml ON ml.id = p.list_id AND ml.company_id = u.company_id
      WHERE p.id = $1 AND u.company_id = $2`,
    [pinId, companyId]
  )).rows[0];
  if (!pin) return { exists: false, pin_exists: false };
  const now = Date.now();
  const visitAt = pin.last_visit_at ? new Date(pin.last_visit_at) : null;
  return {
    ...pin,
    exists: true,
    pin_exists: true,
    pin_id: pin.id,
    has_contact: !!pin.contact_id,
    is_lead: pin.status === "lead",
    is_won: pin.status === "won",
    is_lost: pin.status === "lost",
    is_reloop: pin.status === "reloop",
    is_later: pin.status === "later",
    days_since_visit: visitAt && !Number.isNaN(visitAt.getTime()) ? Math.floor((now - visitAt.getTime()) / 86400000) : null
  };
}

async function loadRouteContext(companyId, routeId) {
  const route = (await ctx.pool.query(
    `SELECT r.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS assigned_user_name
       FROM field_routes r
       LEFT JOIN users u ON u.id = r.assigned_user_id
      WHERE r.id::text = $1 AND r.company_id = $2`,
    [routeId, companyId]
  )).rows[0];
  if (!route) return { exists: false };
  const counts = (await ctx.pool.query(
    `SELECT COUNT(*)::int AS stop_count,
            COUNT(*) FILTER (WHERE status = 'completed')::int AS completed_stop_count,
            COUNT(*) FILTER (WHERE status NOT IN ('completed','skipped'))::int AS remaining_stop_count
       FROM field_route_stops WHERE route_id = $1 AND company_id = $2`,
    [route.id, companyId]
  )).rows[0] || {};
  return { ...route, exists: true, ...counts, all_stops_completed: Number(counts.stop_count || 0) > 0 && Number(counts.remaining_stop_count || 0) === 0 };
}

async function loadRouteStopContext(companyId, stopId) {
  const stop = (await ctx.pool.query(`SELECT * FROM field_route_stops WHERE id::text = $1 AND company_id = $2`, [stopId, companyId])).rows[0];
  if (!stop) return { exists: false };
  return { ...stop, exists: true, completed: stop.status === "completed", skipped: stop.status === "skipped" };
}

async function loadEmployeeContext(companyId, employeeId) {
  const employee = (await ctx.pool.query(`SELECT id, email, role, display_name, photo_url, created_at, deleted_at FROM users WHERE id::text = $1 AND company_id = $2`, [employeeId, companyId])).rows[0];
  if (!employee) return { exists: false };
  const open = (await ctx.pool.query(`SELECT id, start_at FROM time_clock_entries WHERE user_id = $1 AND company_id = $2 AND end_at IS NULL ORDER BY start_at DESC LIMIT 1`, [employee.id, companyId])).rows[0];
  const dayStart = new Date(); dayStart.setUTCHours(0, 0, 0, 0);
  const dayEnd = new Date(dayStart); dayEnd.setUTCDate(dayEnd.getUTCDate() + 1);
  const weekStart = new Date(dayStart); weekStart.setUTCDate(weekStart.getUTCDate() - weekStart.getUTCDay());
  const metrics = (await ctx.pool.query(
    `SELECT
       COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(end_at, now()) - start_at)) - COALESCE(break_seconds,0)) FILTER (WHERE start_at >= $3),0) / 3600 AS hours_today,
       COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(end_at, now()) - start_at)) - COALESCE(break_seconds,0)) FILTER (WHERE start_at >= $4),0) / 3600 AS hours_this_week
       FROM time_clock_entries WHERE user_id = $1 AND company_id = $2 AND manual_status <> 'disapproved'`,
    [employee.id, companyId, dayStart.toISOString(), weekStart.toISOString()]
  )).rows[0] || {};
  const jobs = (await ctx.pool.query(
    `SELECT COUNT(*)::int AS jobs_today,
            COUNT(*) FILTER (WHERE finished_at IS NOT NULL)::int AS completed_jobs_today
       FROM schedule_events
      WHERE company_id = $1 AND (worker_user_ids ? $2 OR sales_user_ids ? $2 OR user_id::text = $2)
        AND start_at >= $3 AND start_at < $4`,
    [companyId, employee.id, dayStart.toISOString(), dayEnd.toISOString()]
  )).rows[0] || {};
  const tasks = (await ctx.pool.query(
    `SELECT COUNT(*) FILTER (WHERE due_date >= $3 AND due_date < $4)::int AS tasks_due_today,
            COUNT(*) FILTER (WHERE due_date < now() AND completed = false)::int AS overdue_tasks
       FROM todo_tasks tt JOIN users u ON u.id = tt.user_id
      WHERE tt.user_id = $1 AND u.company_id = $2`,
    [employee.id, companyId, dayStart.toISOString(), dayEnd.toISOString()]
  )).rows[0] || {};
  return {
    ...employee,
    exists: true,
    name: employee.display_name || employee.email,
    active: !employee.deleted_at,
    is_clocked_in: !!open,
    current_shift_duration: open ? Math.floor((Date.now() - new Date(open.start_at).getTime()) / 60000) : 0,
    hours_today: Number(metrics.hours_today || 0),
    hours_this_week: Number(metrics.hours_this_week || 0),
    jobs_today: Number(jobs.jobs_today || 0),
    completed_jobs_today: Number(jobs.completed_jobs_today || 0),
    tasks_due_today: Number(tasks.tasks_due_today || 0),
    overdue_tasks: Number(tasks.overdue_tasks || 0)
  };
}

async function loadTimeEntryContext(companyId, entryId) {
  const entry = (await ctx.pool.query(
    `SELECT e.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name
       FROM time_clock_entries e JOIN users u ON u.id = e.user_id
      WHERE e.id = $1 AND e.company_id = $2`,
    [entryId, companyId]
  )).rows[0];
  if (!entry) return { exists: false };
  const end = entry.end_at ? new Date(entry.end_at) : new Date();
  const start = new Date(entry.start_at);
  const minutes = Number.isNaN(start.getTime()) ? 0 : Math.max(0, Math.floor((end.getTime() - start.getTime()) / 60000) - Math.floor(Number(entry.break_seconds || 0) / 60));
  return { ...entry, exists: true, employee_clocked_in: !entry.end_at, clock_in_at: entry.start_at, clock_out_at: entry.end_at, clock_in: entry.start_at, clock_out: entry.end_at, shift_duration_minutes: minutes, shift_duration_hours: minutes / 60, duration_hours: minutes / 60 };
}

async function loadMeasurementContext(companyId, measurementId) {
  const measurement = (await ctx.pool.query(
    `SELECT m.* FROM measurements m JOIN users u ON u.id = m.user_id WHERE m.id = $1 AND u.company_id = $2`,
    [measurementId, companyId]
  )).rows[0];
  if (!measurement) return { exists: false };
  const points = Array.isArray(measurement.points) ? measurement.points : [];
  return { ...measurement, exists: true, type: points.length >= 3 ? "area" : "distance", area: polygonAreaApprox(points), distance: pathDistance(points), contact_id: Array.isArray(measurement.linked_contact_ids) ? measurement.linked_contact_ids[0] || null : null, pin_id: null };
}

async function loadTaskContext(companyId, taskId) {
  const task = (await ctx.pool.query(`SELECT tt.* FROM todo_tasks tt JOIN users u ON u.id = tt.user_id WHERE tt.id = $1 AND u.company_id = $2`, [taskId, companyId])).rows[0];
  if (!task) return { exists: false };
  const subtasks = Array.isArray(task.subtasks) ? task.subtasks : [];
  const completedSubtasks = subtasks.filter((s) => s?.completed).length;
  return { ...task, exists: true, due_at: task.due_date, overdue: task.due_date ? new Date(task.due_date) < new Date() && !task.completed : false, assigned_user: task.user_id, subtask_count: subtasks.length, completed_subtask_count: completedSubtasks, all_subtasks_completed: subtasks.length > 0 && completedSubtasks === subtasks.length };
}

async function loadJobContext(companyId, jobId) {
  const job = (await ctx.pool.query(`SELECT * FROM schedule_events WHERE id = $1 AND company_id = $2`, [jobId, companyId])).rows[0];
  if (!job) return { exists: false };
  const workers = await userNames(companyId, jsonArray(job.worker_user_ids));
  const sales = await userNames(companyId, jsonArray(job.sales_user_ids));
  const start = new Date(job.start_at);
  const end = new Date(job.end_at);
  return {
    ...job,
    exists: true,
    start: job.start_at,
    end: job.end_at,
    duration: Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) ? null : Math.round((end.getTime() - start.getTime()) / 60000),
    completed: !!job.finished_at,
    canceled: false,
    deleted: false,
    overdue: !job.finished_at && !Number.isNaN(end.getTime()) && end < new Date(),
    services: normalizeServiceItems(job.service_items || job.services || []).map((s) => s.name),
    worker_ids: jsonArray(job.worker_user_ids),
    salesperson_ids: jsonArray(job.sales_user_ids),
    worker_names: workers,
    salesperson_names: sales,
    has_workers: jsonArray(job.worker_user_ids).length > 0,
    has_salesperson: jsonArray(job.sales_user_ids).length > 0,
    source: "schedule"
  };
}

async function userNames(companyId, ids) {
  if (!ids.length) return [];
  return (await ctx.pool.query(`SELECT display_name, email FROM users WHERE company_id = $1 AND id = ANY($2::uuid[])`, [companyId, ids])).rows.map((r) => r.display_name || r.email || "");
}

async function loadRoutineContext(companyId, routineId) {
  const routine = (await ctx.pool.query(`SELECT tr.* FROM todo_routines tr JOIN users u ON u.id = tr.user_id WHERE tr.id = $1 AND u.company_id = $2`, [routineId, companyId])).rows[0];
  if (!routine) return { exists: false };
  const dayKey = new Date().toISOString().slice(0, 10);
  const done = await ctx.pool.query(`SELECT 1 FROM todo_routine_done rd JOIN users u ON u.id = rd.user_id WHERE rd.routine_id = $1 AND rd.day_key = $2 AND u.company_id = $3 LIMIT 1`, [routineId, dayKey, companyId]);
  return { ...routine, exists: true, active: !!routine.enabled, completed_today: done.rowCount > 0, due_today: Array.isArray(routine.weekdays) ? routine.weekdays.includes(new Date().getDay() + 1) : false, missed_today: done.rowCount === 0 };
}

async function loadCustomerReminderContext(companyId, reminderId) {
  const reminder = (await ctx.pool.query(`SELECT cr.* FROM todo_customer_reminders cr JOIN users u ON u.id = cr.user_id WHERE cr.id = $1 AND u.company_id = $2`, [reminderId, companyId])).rows[0];
  if (!reminder) return { exists: false };
  return { ...reminder, exists: true, due_at: reminder.due_date, overdue: reminder.due_date ? new Date(reminder.due_date) < new Date() && !reminder.completed : false };
}

async function loadContactContext(companyId, contactId) {
  const contact = (await ctx.pool.query(
    `SELECT id, name, phone, email, address, value_cents, lat, lng, tags, job_type, u1, u2, u3, u4, u5,
            lead_info, source, external_lead_id, lead_form_id, lead_page_id, lead_submitted_at, created_at, updated_at
       FROM contacts WHERE id::text = $1 AND company_id = $2`,
    [contactId, companyId]
  )).rows[0];
  if (!contact) return { exists: false };
  const addressParts = parseAddressParts(contact.address || "");
  const rel = await loadContactRelationshipFlags(companyId, contact.id);
  return {
    ...contact,
    exists: true,
    tags: normalizeTags(contact.tags),
    value: contact.value_cents == null ? null : Number(contact.value_cents) / 100,
    has_phone: Boolean((contact.phone || "").trim()),
    has_email: Boolean((contact.email || "").trim()),
    has_address: Boolean((contact.address || "").trim()),
    ...addressParts,
    ...rel
  };
}

async function loadContactRelationshipFlags(companyId, contactId) {
  const [futureJob, completedJob, quote, unpaidPayment, activePlan, mapPin] = await Promise.all([
    ctx.pool.query(`SELECT 1 FROM schedule_events WHERE company_id = $1 AND contact_id = $2 AND start_at > now() LIMIT 1`, [companyId, contactId]),
    ctx.pool.query(`SELECT 1 FROM schedule_events WHERE company_id = $1 AND contact_id = $2 AND finished_at IS NOT NULL LIMIT 1`, [companyId, contactId]),
    ctx.pool.query(`SELECT 1 FROM quotes WHERE company_id = $1 AND contact_id = $2 LIMIT 1`, [companyId, contactId]),
    ctx.pool.query(`SELECT 1 FROM payment_records WHERE company_id = $1 AND contact_id = $2 AND status NOT IN ('succeeded','paid') LIMIT 1`, [companyId, contactId]).catch(() => ({ rowCount: 0 })),
    ctx.pool.query(`SELECT 1 FROM service_plans WHERE company_id = $1 AND contact_id = $2 AND status = 'active' LIMIT 1`, [companyId, contactId]).catch(() => ({ rowCount: 0 })),
    ctx.pool.query(`SELECT 1 FROM map_pins mp JOIN users u ON u.id = mp.user_id WHERE u.company_id = $1 AND mp.contact_id = $2 LIMIT 1`, [companyId, contactId])
  ]);
  return {
    has_future_scheduled_job: futureJob.rowCount > 0,
    has_previous_completed_job: completedJob.rowCount > 0,
    has_quote: quote.rowCount > 0,
    has_unpaid_payment: unpaidPayment.rowCount > 0,
    has_active_service_plan: activePlan.rowCount > 0,
    exists_on_map: mapPin.rowCount > 0
  };
}

function leadContextFromContact(contact, payload) {
  const leadInfo = Array.isArray(contact.lead_info) ? contact.lead_info : [];
  return {
    source: contact.source || payload.source || null,
    external_id: contact.external_lead_id || payload.external_lead_id || null,
    form_id: contact.lead_form_id || payload.form_id || null,
    page_id: contact.lead_page_id || payload.page_id || null,
    submitted_at: contact.lead_submitted_at || payload.submitted_at || null,
    has_lead_info: leadInfo.length > 0,
    info: leadInfo
  };
}

async function loadPipelineContext(companyId, contactId) {
  const opp = (await ctx.pool.query(
    `SELECT o.*, s.name AS stage_name, c.value_cents, u.name AS salesperson_name
       FROM opportunities o
       LEFT JOIN stages s ON s.id = o.stage_id AND (s.company_id = $1 OR s.company_id IS NULL)
       LEFT JOIN contacts c ON c.id::text = o.contact_id AND c.company_id = $1
       LEFT JOIN users u ON u.id = o.user_id AND u.company_id = $1
      WHERE o.company_id = $1 AND o.contact_id = $2
      LIMIT 1`,
    [companyId, contactId]
  )).rows[0];
  const reminder = await ctx.pool.query(`SELECT 1 FROM stage_reminders WHERE contact_id = $1 AND archived = false LIMIT 1`, [contactId]);
  if (!opp) return { has_opportunity: false, reminder_exists: reminder.rowCount > 0 };
  const created = opp.updated_at || opp.created_at;
  return {
    has_opportunity: true,
    opportunity_id: opp.id,
    stage_id: opp.stage_id,
    stage_name: opp.stage_name,
    is_won: opp.state === "won",
    is_lost: opp.state === "lost",
    opportunity_value: opp.value_cents == null ? null : Number(opp.value_cents) / 100,
    salesperson_id: opp.user_id,
    salesperson_name: opp.salesperson_name,
    days_in_stage: created ? Math.floor((Date.now() - new Date(created).getTime()) / 86400000) : null,
    reminder_exists: reminder.rowCount > 0
  };
}

function parseAddressParts(address) {
  const zip = (address.match(/\b\d{5}(?:-\d{4})?\b/) || [null])[0];
  return { city: null, state: null, zip };
}

function subjectContextKey(type) {
  if (type === "sms_conversation" || type === "sms_message") return "sms";
  if (type === "service_plan") return "servicePlan";
  if (type === "internal_message" || type === "internal_conversation") return "internal";
  if (type === "map_pin") return "map";
  if (type === "route_stop") return "routeStop";
  if (type === "time_entry") return "time_clock";
  return type;
}

async function loadSmsMessageContext(companyId, messageId) {
  const row = (await ctx.pool.query(
    `SELECT sm.*, sc.external_phone_number, sc.contact_id, sc.last_read_at, pl.phone_number AS business_phone
       FROM sms_messages sm
       JOIN sms_conversations sc ON sc.id = sm.conversation_id
       JOIN phone_lines pl ON pl.id = sc.phone_line_id
      WHERE sm.id = $1 AND pl.company_id = $2`,
    [messageId, companyId]
  )).rows[0];
  if (!row) return { exists: false };
  return smsContextFromRow(companyId, row);
}

async function loadSmsConversationContext(companyId, conversationId) {
  const last = (await ctx.pool.query(
    `SELECT sm.*, sc.external_phone_number, sc.contact_id, sc.last_read_at, pl.phone_number AS business_phone
       FROM sms_conversations sc
       JOIN phone_lines pl ON pl.id = sc.phone_line_id
       LEFT JOIN LATERAL (
         SELECT * FROM sms_messages m WHERE m.conversation_id = sc.id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1
       ) sm ON true
      WHERE sc.id = $1 AND pl.company_id = $2`,
    [conversationId, companyId]
  )).rows[0];
  if (!last) return { exists: false };
  return smsContextFromRow(companyId, last);
}

async function smsContextFromRow(companyId, row) {
  const counts = (await ctx.pool.query(
    `SELECT COUNT(*)::int AS message_count,
            COUNT(*) FILTER (WHERE direction = 'inbound')::int AS inbound_count,
            COUNT(*) FILTER (WHERE direction = 'outbound')::int AS outbound_count,
            MAX(created_at) FILTER (WHERE direction = 'inbound') AS last_inbound_at,
            MAX(created_at) FILTER (WHERE direction = 'outbound') AS last_outbound_at
       FROM sms_messages WHERE conversation_id = $1 AND deleted_at IS NULL`,
    [row.conversation_id]
  )).rows[0] || {};
  const optedOut = await isPhoneOptedOut(companyId, row.external_phone_number || row.from_number || row.to_number);
  return {
    exists: true,
    id: row.id,
    message_id: row.id,
    conversation_id: row.conversation_id,
    body: row.body || "",
    from: row.from_number,
    to: row.to_number,
    external_number: row.external_phone_number,
    business_phone: row.business_phone,
    direction: row.direction,
    status: row.message_status,
    contact_id: row.contact_id,
    contact_exists: !!row.contact_id,
    has_media: Number(row.media_count || 0) > 0,
    media_count: Number(row.media_count || 0),
    is_reply: row.direction === "inbound" && !!counts.last_outbound_at,
    reply_latency_seconds: row.direction === "inbound" && counts.last_outbound_at ? Math.max(0, Math.round((new Date(row.created_at).getTime() - new Date(counts.last_outbound_at).getTime()) / 1000)) : null,
    messages_count: Number(counts.message_count || 0),
    inbound_count: Number(counts.inbound_count || 0),
    outbound_count: Number(counts.outbound_count || 0),
    last_inbound_at: counts.last_inbound_at,
    last_outbound_at: counts.last_outbound_at,
    sms_opted_out: optedOut,
    is_business_hours: true,
    is_after_hours: false
  };
}

async function loadCallContext(companyId, callId) {
  const call = (await ctx.pool.query(`SELECT * FROM phone_calls WHERE id = $1 AND company_id = $2`, [callId, companyId])).rows[0];
  if (!call) return { exists: false };
  const external = call.direction === "inbound" ? call.from_number : call.to_number;
  return { ...call, exists: true, external_number: external, contact_exists: !!call.contact_id, is_missed: call.direction === "inbound" && ["missed", "busy", "failed", "no-answer", "canceled"].includes(String(call.disposition || call.status || "").toLowerCase()), is_after_hours: false, answered: !!call.answered_at, failed: ["failed", "busy", "no-answer"].includes(String(call.disposition || call.status || "").toLowerCase()) };
}

async function loadVoicemailContext(companyId, voicemailId) {
  const vm = (await ctx.pool.query(`SELECT * FROM voicemails WHERE id = $1 AND company_id = $2`, [voicemailId, companyId])).rows[0];
  if (!vm) return { exists: false };
  return { ...vm, exists: true, read: !!vm.is_read, duration: vm.duration_seconds, contact_exists: !!vm.contact_id, external_number: vm.external_phone_number, received_at: vm.created_at, age: Math.max(0, Math.round((Date.now() - new Date(vm.created_at).getTime()) / 1000)) };
}

async function loadInternalMessageContext(companyId, messageId) {
  const msg = (await ctx.pool.query(
    `SELECT m.*, u.display_name AS sender_name, ch.name AS channel_name, c.is_group,
            (SELECT COUNT(*)::int FROM message_attachments a WHERE a.message_id = m.id) AS attachment_count
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       LEFT JOIN channels ch ON ch.id = m.channel_id
       LEFT JOIN conversations c ON c.id = m.conversation_id
      WHERE m.id = $1 AND u.company_id = $2`,
    [messageId, companyId]
  )).rows[0];
  if (!msg) return { exists: false };
  return { message: { body: msg.body, has_attachment: Number(msg.attachment_count || 0) > 0 }, message_body: msg.body, sender_id: msg.sender_id, sender_name: msg.sender_name, channel_id: msg.channel_id, channel_name: msg.channel_name, conversation_id: msg.conversation_id, conversation_type: msg.channel_id ? "channel" : msg.is_group ? "group" : "dm", is_dm: !msg.channel_id && !msg.is_group, is_group: !!msg.is_group, is_channel: !!msg.channel_id };
}

async function loadInternalConversationContext(companyId, conversationId) {
  const conv = (await ctx.pool.query(`SELECT * FROM conversations WHERE id = $1 AND company_id = $2`, [conversationId, companyId])).rows[0];
  return conv ? { ...conv, exists: true, is_dm: !conv.is_group, is_group: !!conv.is_group } : { exists: false };
}

async function loadChannelContext(companyId, channelId) {
  const channel = (await ctx.pool.query(`SELECT * FROM channels WHERE id = $1 AND company_id = $2`, [channelId, companyId])).rows[0];
  return channel ? { ...channel, exists: true } : { exists: false };
}

function resolveTemplate(value, context) {
  if (value == null) return "";
  if (typeof value !== "string") return value;
  return value.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_m, path) => {
    const found = getPath(context, path.trim());
    if (found == null) return "";
    if (typeof found === "object") return JSON.stringify(found);
    return String(found);
  });
}

function resolveConfig(config, context) {
  if (Array.isArray(config)) return config.map((v) => resolveConfig(v, context));
  if (config && typeof config === "object") return Object.fromEntries(Object.entries(config).map(([k, v]) => [k, resolveConfig(v, context)]));
  return resolveTemplate(config, context);
}

function getPath(root, path) {
  if (!isSafeObjectPath(path)) return undefined;
  return String(path || "").split(".").reduce((acc, key) => (acc == null ? undefined : acc[key]), root);
}

function isSafeObjectPath(path) {
  return String(path || "").split(".").every((part) => part && !["__proto__", "constructor", "prototype"].includes(part));
}

function resolveRawValue(value, context) {
  if (typeof value !== "string") return value;
  const match = value.trim().match(/^\{\{\s*([^}]+?)\s*\}\}$/);
  if (match) return getPath(context, match[1].trim());
  return resolveTemplate(value, context);
}

function resolveCollection(value, context, options = {}) {
  const raw = resolveRawValue(value, context);
  let items = raw;
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed && options.nullAsEmpty !== false) return [];
    if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
      try { items = JSON.parse(trimmed); } catch { items = raw; }
    }
  }
  if (items == null && options.nullAsEmpty !== false) return [];
  if (!Array.isArray(items)) throw new Error("collection_required");
  return capCollection(items, options.maxItems || AUTOMATION_LIMITS.maxCollectionOutputItems);
}

function capCollection(items, maxItems = AUTOMATION_LIMITS.maxCollectionOutputItems) {
  const capped = items.slice(0, Math.max(0, Math.min(maxItems, AUTOMATION_LIMITS.maxCollectionOutputItems)));
  return capped.map((item) => safeJsonLimited(item));
}

function safeJsonLimited(value) {
  const safe = safeJson(value);
  const serialized = JSON.stringify(safe);
  if (serialized.length <= AUTOMATION_LIMITS.maxJsonBytes) return safe;
  if (Array.isArray(safe)) return safe.slice(0, 25);
  if (safe && typeof safe === "object") return { truncated: true, keys: Object.keys(safe).slice(0, 50) };
  return String(safe).slice(0, 1000);
}

function stablePortId(value) {
  const cleaned = String(value || "default").trim().toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
  return cleaned || "default";
}

function normalizeDynamicPorts(config, fallback = ["path_a", "path_b"]) {
  const raw = Array.isArray(config?.paths) ? config.paths : fallback.map((id) => ({ id, label: id, weight: 50 }));
  return raw.map((path, index) => {
    if (typeof path === "string") return { id: stablePortId(path), label: path, weight: index === 0 ? 50 : 50 };
    const label = path.label || path.name || path.id || `Path ${index + 1}`;
    return { ...path, id: stablePortId(path.id || label), label, weight: Number(path.weight ?? path.percentage ?? 0) };
  }).filter((path) => path.id);
}

function hashNumber(input) {
  let h = 2166136261;
  for (const ch of String(input)) {
    h ^= ch.charCodeAt(0);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967296;
}

function parseJsonObject(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string" && value.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

function evaluateCondition(config, context) {
  if (!config || typeof config !== "object") return true;
  const operator = (config.operator || "equals").toString().toLowerCase();
  if (["all", "and"].includes(operator)) return (config.conditions || []).every((c) => evaluateCondition(c, context));
  if (["any", "or"].includes(operator)) return (config.conditions || []).some((c) => evaluateCondition(c, context));
  if (operator === "not") return !(config.conditions || []).some((c) => evaluateCondition(c, context));
  const left = config.field ? getPath(context, config.field) : resolveTemplate(config.left ?? "", context);
  const right = typeof config.value === "string" ? resolveTemplate(config.value, context) : config.value;
  switch (operator) {
    case "equals": return looseEqual(left, right);
    case "not_equals": return !looseEqual(left, right);
    case "contains": return containsValue(left, right);
    case "not_contains": return !containsValue(left, right);
    case "starts_with": return String(left || "").startsWith(String(right || ""));
    case "ends_with": return String(left || "").endsWith(String(right || ""));
    case "exists": return left != null && left !== "";
    case "not_exists": return left == null || left === "";
    case "greater_than": return Number(left) > Number(right);
    case "greater_or_equal": return Number(left) >= Number(right);
    case "less_than": return Number(left) < Number(right);
    case "less_or_equal": return Number(left) <= Number(right);
    case "before": return new Date(left) < new Date(right);
    case "after": return new Date(left) > new Date(right);
    case "between": return new Date(left) >= new Date(config.start || right?.[0]) && new Date(left) <= new Date(config.end || right?.[1]);
    case "in": return Array.isArray(right) ? right.some((v) => looseEqual(v, left)) : false;
    case "not_in": return Array.isArray(right) ? !right.some((v) => looseEqual(v, left)) : true;
    case "is_true": return left === true || left === "true" || left === 1;
    case "is_false": return left === false || left === "false" || left === 0;
    default: return false;
  }
}

function looseEqual(a, b) {
  return String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
}

function containsValue(left, right) {
  if (Array.isArray(left)) return left.map((v) => String(v).toLowerCase()).includes(String(right).toLowerCase());
  return String(left ?? "").toLowerCase().includes(String(right ?? "").toLowerCase());
}

async function executeContactAddTag(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const tags = normalizeTags(resolveConfig(config.tags || config.tag || [], context));
  const result = await mutateContactTags(run.company_id, contactId, (existing) => uniqueTags([...existing, ...tags]));
  await emitContactTagEvents(run, node, contactId, result);
  return { contact_id: contactId, tags: result.next, added_tags: result.added };
}

async function executeContactRemoveTag(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const tags = normalizeTags(resolveConfig(config.tags || config.tag || [], context)).map((t) => t.toLowerCase());
  const result = await mutateContactTags(run.company_id, contactId, (existing) => existing.filter((t) => !tags.includes(t.toLowerCase())));
  await emitContactTagEvents(run, node, contactId, result);
  return { contact_id: contactId, tags: result.next, removed_tags: result.removed };
}

async function executeContactUpdateFields(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const allowed = ["name", "phone", "email", "address", "job_type", "source", "u1", "u2", "u3", "u4", "u5", "value_cents", "lat", "lng"];
  const updates = {};
  for (const field of allowed) if (config[field] != null) updates[field] = resolveTemplate(config[field], context);
  if (!Object.keys(updates).length) return { contact_id: contactId, updated: [] };
  const before = (await ctx.pool.query(`SELECT * FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, run.company_id])).rows[0];
  const sets = Object.keys(updates).map((key, i) => `${key} = $${i + 3}`);
  const { rows } = await ctx.pool.query(
    `UPDATE contacts SET ${sets.join(", ")}, updated_at = now() WHERE id::text = $1 AND company_id = $2 RETURNING *`,
    [contactId, run.company_id, ...Object.values(updates)]
  );
  if (!rows.length) throw new Error("contact_not_found");
  const changed = contactChangedFields(before, rows[0], Object.keys(updates));
  await emitContactChangeEvents(run.company_id, contactId, "automation", run.manual_started_by_user_id, changed, automationPayload(run, node, { contact_id: contactId }));
  return { contact_id: contactId, updated: changed.map((f) => f.field) };
}

async function resolveContactId(run, context, config) {
  const id = resolveTemplate(config.contact_id || context.contact?.id || (run.subject_type === "contact" ? run.subject_id : ""), context);
  if (!id) throw new Error("contact_id_required");
  const exists = await ctx.pool.query(`SELECT id FROM contacts WHERE id::text = $1 AND company_id = $2`, [id, run.company_id]);
  if (!exists.rowCount) throw new Error("contact_not_found");
  return id;
}

async function mutateContactTags(companyId, contactId, mutator) {
  const row = (await ctx.pool.query(`SELECT tags FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, companyId])).rows[0];
  if (!row) throw new Error("contact_not_found");
  const current = normalizeTags(row.tags);
  const next = uniqueTags(mutator(current).filter(Boolean));
  const currentLower = current.map((t) => t.toLowerCase());
  const nextLower = next.map((t) => t.toLowerCase());
  const added = next.filter((t) => !currentLower.includes(t.toLowerCase()));
  const removed = current.filter((t) => !nextLower.includes(t.toLowerCase()));
  const type = (await ctx.pool.query(`SELECT data_type, udt_name FROM information_schema.columns WHERE table_name = 'contacts' AND column_name = 'tags' LIMIT 1`)).rows[0];
  const value = type?.udt_name?.startsWith("_") ? next : next.join(",");
  await ctx.pool.query(`UPDATE contacts SET tags = $3, updated_at = now() WHERE id::text = $1 AND company_id = $2`, [contactId, companyId, value]);
  return { previous: current, next, added, removed };
}

function normalizeTags(value) {
  if (Array.isArray(value)) return value.flatMap(normalizeTags);
  if (value == null) return [];
  return String(value).split(",").map((t) => t.trim()).filter(Boolean);
}

function uniqueTags(tags) {
  const seen = new Set();
  const out = [];
  for (const tag of normalizeTags(tags)) {
    const key = tag.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      out.push(tag);
    }
  }
  return out;
}

async function executeContactCreate(run, node, config) {
  const existingId = await getRunVariable(run.id, `idempotency:${node.id}:contact_id`);
  if (existingId) {
    const existing = await loadContactContext(run.company_id, existingId);
    if (existing?.exists) return { contact_id: existingId, reused: true };
  }
  const context = await buildRunContext(run);
  const fields = resolveConfig(config, context);
  const name = (fields.name || "").toString().trim();
  if (!name) throw new Error("contact_name_required");
  const owner = await resolveCompanyUser(run.company_id, fields.assigned_user_id || "");
  const id = randomUUID();
  const tags = uniqueTags(fields.tags || []);
  const { rows } = await ctx.pool.query(
    `INSERT INTO contacts(id, user_id, company_id, name, phone, email, address, value_cents, lat, lng, tags, job_type, u1, u2, u3, u4, u5, source)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
     RETURNING *`,
    [id, owner, run.company_id, name, fields.phone || "", fields.email || "", fields.address || "", intOrNull(fields.value_cents), numOrNull(fields.lat), numOrNull(fields.lng), tags.join(","), fields.job_type || "", fields.u1 || "", fields.u2 || "", fields.u3 || "", fields.u4 || "", fields.u5 || "", fields.source || "automation"]
  );
  await setRunVariable(run.id, `idempotency:${node.id}:contact_id`, id);
  await emitAutomationEvent({
    companyId: run.company_id,
    eventType: "contact.created",
    subjectType: "contact",
    subjectId: id,
    source: "automation",
    dedupeKey: `contact.created:${id}`,
    payload: automationPayload(run, node, { contact_id: id, name, source: fields.source || "automation" })
  });
  return { contact_id: id, name: rows[0].name, phone: rows[0].phone, email: rows[0].email };
}

async function executeContactDelete(run, node, config) {
  if (config.confirm_delete !== true) throw new Error("confirm_delete_required");
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const row = (await ctx.pool.query(`SELECT id, name FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, run.company_id])).rows[0];
  if (!row) throw new Error("contact_not_found");
  await ctx.pool.query(`UPDATE schedule_events SET contact_id = NULL, updated_at = now() WHERE contact_id = $1 AND company_id = $2`, [contactId, run.company_id]);
  await ctx.pool.query(`DELETE FROM opportunities WHERE contact_id = $1 AND company_id = $2`, [contactId, run.company_id]);
  await ctx.pool.query(`DELETE FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, run.company_id]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "contact.deleted", subjectType: "contact", subjectId: contactId, source: "automation", dedupeKey: `contact.deleted:${contactId}:${run.id}:${node.id}`, payload: automationPayload(run, node, { contact_id: contactId, name: row.name }) });
  return { contact_id: contactId, deleted: true };
}

async function executeDeferredAction(_run, _node, config) {
  throw new Error(config?.deferred_reason || "action_deferred_current_schema_does_not_support_this");
}

async function executeContactReplaceTags(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const result = await mutateContactTags(run.company_id, contactId, () => uniqueTags(resolveConfig(config.tags || [], context)));
  await emitContactTagEvents(run, node, contactId, result);
  return { contact_id: contactId, tags: result.next, added_tags: result.added, removed_tags: result.removed };
}

async function executeContactClearTags(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const result = await mutateContactTags(run.company_id, contactId, () => []);
  await emitContactTagEvents(run, node, contactId, result);
  return { contact_id: contactId, tags: [] };
}

async function executeContactSetSource(run, node, config) { return executeContactUpdateFields(run, node, { ...config, source: config.source }); }
async function executeContactSetValue(run, node, config) { return executeContactUpdateFields(run, node, { ...config, value_cents: config.value_cents ?? config.value }); }
async function executeContactSetJobType(run, node, config) { return executeContactUpdateFields(run, node, { ...config, job_type: config.job_type }); }
async function executeContactSetLocation(run, node, config) { return executeContactUpdateFields(run, node, { ...config, lat: config.lat, lng: config.lng }); }

async function executeContactSetCustomField(run, node, config) {
  const field = (config.field || "").toString();
  if (!["u1", "u2", "u3", "u4", "u5"].includes(field)) throw new Error("invalid_custom_field");
  return executeContactUpdateFields(run, node, { contact_id: config.contact_id, [field]: config.value });
}

async function executeContactAddNote(run, node, config) {
  return insertContactActivity(run, node, { ...config, activity_type: "note" });
}

async function executeContactAddActivity(run, node, config) {
  return insertContactActivity(run, node, config);
}

async function insertContactActivity(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const body = resolveTemplate(config.body || config.note || "", context).trim();
  if (!body) throw new Error("activity_body_required");
  const type = ["note", "call", "message", "email"].includes(config.activity_type) ? config.activity_type : "note";
  const owner = await resolveCompanyUser(run.company_id, "");
  const { rows } = await ctx.pool.query(
    `INSERT INTO contact_activities(company_id, contact_id, created_by_user_id, activity_type, body, source, automation_run_id, automation_node_id)
     VALUES($1,$2,$3,$4,$5,'automation',$6,$7) RETURNING id, contact_id, activity_type, body, created_at`,
    [run.company_id, contactId, owner, type, body, run.id, node.id]
  );
  return rows[0];
}

async function executeContactAddToMap(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const contact = await loadContactContext(run.company_id, contactId);
  const lat = numOrNull(config.lat ?? contact.lat);
  const lng = numOrNull(config.lng ?? contact.lng);
  if (lat == null || lng == null) throw new Error("contact_coordinates_required");
  const owner = await resolveCompanyUser(run.company_id, "");
  const id = randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO map_pins(id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [id, owner, lat, lng, contact.name || "", contact.address || "", resolveTemplate(config.notes || "", context), config.status || "lead", contact.phone || null, contact.email || null, contactId]
  );
  await emitMapPinEvents(run.company_id, null, rows[0], "automation", null, automationPayload(run, node, { pin_id: id, contact_id: contactId }));
  return { pin_id: rows[0].id, contact_id: contactId };
}

async function executeMapCreatePin(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:pin_id`);
  if (existing) {
    const pin = await loadMapPinContext(run.company_id, existing);
    if (pin?.exists) return { pin_id: existing, reused: true };
  }
  const context = await buildRunContext(run);
  const fields = resolveConfig(config, context);
  const contact = fields.contact_id ? await loadContactContext(run.company_id, fields.contact_id) : context.contact;
  const lat = numOrNull(fields.latitude ?? fields.lat ?? contact?.lat ?? context.map?.latitude);
  const lng = numOrNull(fields.longitude ?? fields.lng ?? contact?.lng ?? context.map?.longitude);
  const address = resolveTemplate(fields.address || contact?.address || context.map?.address || "", context);
  if ((lat == null || lng == null) && !address) throw new Error("map_pin_location_required");
  if (lat == null || lng == null) throw new Error("backend_geocoding_not_configured_coordinates_required");
  const owner = await resolveCompanyUser(run.company_id, fields.assigned_user_id || fields.owner_user_id || "");
  const id = randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO map_pins(id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id, list_id, source)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [id, owner, lat, lng, resolveTemplate(fields.name || contact?.name || "", context), address, resolveTemplate(fields.notes || "", context), normalizeMapStatus(fields.status), fields.phone || contact?.phone || null, fields.email || contact?.email || null, fields.contact_id || contact?.id || null, fields.list_id || null, "automation"]
  );
  await setRunVariable(run.id, `idempotency:${node.id}:pin_id`, id);
  await emitMapPinEvents(run.company_id, null, rows[0], "automation", null, automationPayload(run, node, { pin_id: id, contact_id: rows[0].contact_id || null }));
  return { pin_id: id, lat, lng, address, status: rows[0].status, contact_id: rows[0].contact_id || null };
}

async function executeMapUpdatePin(run, node, config) {
  const context = await buildRunContext(run);
  const pin = await resolveMapPin(run.company_id, config.pin_id || run.subject_id, context);
  const fields = resolveConfig(config, context);
  const updates = {};
  for (const key of ["name", "address", "notes", "phone", "email", "contact_id", "list_id"]) if (fields[key] != null) updates[key] = fields[key];
  if (fields.status != null) updates.status = normalizeMapStatus(fields.status);
  if (fields.latitude != null || fields.lat != null) updates.latitude = numOrNull(fields.latitude ?? fields.lat);
  if (fields.longitude != null || fields.lng != null) updates.longitude = numOrNull(fields.longitude ?? fields.lng);
  if (!Object.keys(updates).length) return { pin_id: pin.id, updated: [] };
  const before = { ...pin };
  const sets = Object.keys(updates).map((key, i) => `${key} = $${i + 3}`);
  const values = Object.values(updates);
  const { rows } = await ctx.pool.query(`UPDATE map_pins SET ${sets.join(", ")}, updated_at = now() WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2) RETURNING *`, [pin.id, run.company_id, ...values]);
  await emitMapPinEvents(run.company_id, before, rows[0], "automation", null, automationPayload(run, node, { pin_id: pin.id }));
  return { pin_id: pin.id, updated: Object.keys(updates) };
}

async function executeMapDeletePin(run, node, config) {
  if (config.confirm_delete !== true) throw new Error("confirm_delete_required");
  const context = await buildRunContext(run);
  const pin = await resolveMapPin(run.company_id, config.pin_id || run.subject_id, context);
  await ctx.pool.query(`DELETE FROM map_pins WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2)`, [pin.id, run.company_id]);
  await cancelScheduledForSubject(run.company_id, "map_pin", pin.id, ["map.pin_followup_due"]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "map.pin_deleted", subjectType: "map_pin", subjectId: pin.id, source: "automation", payload: automationPayload(run, node, mapPinPayload(pin)) });
  return { pin_id: pin.id, deleted: true };
}

async function executeMapSetStatus(run, node, config) {
  return executeMapUpdatePin(run, node, { ...config, status: config.status });
}

async function executeMapAddToList(run, node, config) {
  const listId = await resolveMapListId(run.company_id, config.list_id, config.list_name, run.manual_started_by_user_id);
  return executeMapUpdatePin(run, node, { ...config, list_id: listId });
}

async function executeMapMoveToList(run, node, config) {
  return executeMapAddToList(run, node, config);
}

async function executeMapRemoveFromList(run, node, config) {
  return executeMapUpdatePin(run, node, { ...config, list_id: null });
}

async function executeMapLinkContact(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  await validateSubject(run.company_id, "contact", contactId);
  return executeMapUpdatePin(run, node, { ...config, contact_id: contactId });
}

async function executeMapUnlinkContact(run, node, config) {
  return executeMapUpdatePin(run, node, { ...config, contact_id: null });
}

async function executeMapCreateContact(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:map_contact_id`);
  if (existing) return { contact_id: existing, reused: true };
  const context = await buildRunContext(run);
  const pin = await resolveMapPin(run.company_id, config.pin_id || run.subject_id, context);
  if (pin.contact_id) return { contact_id: pin.contact_id, pin_id: pin.id, reused: true };
  const contact = await executeContactCreate(run, node, {
    name: config.name || pin.name || "Door Knock Lead",
    phone: config.phone || pin.phone || "",
    email: config.email || pin.email || "",
    address: pin.address || config.address || "",
    lat: pin.latitude,
    lng: pin.longitude,
    tags: config.tags || ["Door Knock"],
    job_type: config.job_type || "",
    value_cents: config.value_cents,
    source: "map"
  });
  await setRunVariable(run.id, `idempotency:${node.id}:map_contact_id`, contact.contact_id);
  await executeMapUpdatePin(run, node, { pin_id: pin.id, contact_id: contact.contact_id });
  await emitAutomationEvent({ companyId: run.company_id, eventType: "map.pin_converted_to_contact", subjectType: "map_pin", subjectId: pin.id, source: "automation", payload: automationPayload(run, node, { pin_id: pin.id, contact_id: contact.contact_id }) });
  await emitAutomationEvent({ companyId: run.company_id, eventType: "contact.converted_from_map_pin", subjectType: "contact", subjectId: contact.contact_id, source: "automation", payload: automationPayload(run, node, { pin_id: pin.id, contact_id: contact.contact_id }) });
  return { pin_id: pin.id, contact_id: contact.contact_id };
}

async function executeMapAddNote(run, node, config) {
  return insertMapActivity(run, node, "note", config);
}

async function executeMapMarkVisited(run, node, config) {
  return insertMapActivity(run, node, "visit", config);
}

async function executeMapRecordKnock(run, node, config) {
  const result = await insertMapActivity(run, node, "knock", config);
  if (config.outcome_status) await executeMapUpdatePin(run, node, { pin_id: result.pin_id, status: config.outcome_status });
  return result;
}

async function executeMapScheduleFollowup(run, node, config) {
  const context = await buildRunContext(run);
  const pin = await resolveMapPin(run.company_id, config.pin_id || run.subject_id, context);
  const amount = Number(config.amount || 0);
  const unit = config.unit || "days";
  if (amount <= 0) throw new Error("followup_amount_required");
  const when = new Date(Date.now() + durationAmountMs(amount, unit));
  await enqueueScheduledAutomationEvent({
    companyId: run.company_id,
    eventType: "map.pin_followup_due",
    subjectType: "map_pin",
    subjectId: pin.id,
    scheduledFor: when,
    scheduleKey: `map.pin_followup_due:manual:${run.id}:${node.id}:${pin.id}`,
    payload: automationPayload(run, node, { pin_id: pin.id, status: pin.status, amount, unit })
  });
  return { pin_id: pin.id, followup_at: when.toISOString() };
}

async function executeMapAddToRoute(run, node, config) {
  return executeRouteAddPin(run, node, config);
}

async function resolveMapPin(companyId, pinId, context = {}) {
  const id = pinId || context.map?.id || context.map?.pin_id;
  if (!id) throw new Error("map_pin_required");
  const pin = (await ctx.pool.query(`SELECT p.* FROM map_pins p JOIN users u ON u.id = p.user_id WHERE p.id = $1 AND u.company_id = $2`, [id, companyId])).rows[0];
  if (!pin) throw new Error("map_pin_not_found");
  return pin;
}

async function resolveMapListId(companyId, listId, listName, createdByUserId = null) {
  if (listId) {
    const found = await ctx.pool.query(`SELECT id FROM map_lists WHERE id::text = $1 AND company_id = $2`, [listId, companyId]);
    if (!found.rowCount) throw new Error("map_list_not_found");
    return found.rows[0].id;
  }
  const name = String(listName || "").trim();
  if (!name) throw new Error("map_list_required");
  const { rows } = await ctx.pool.query(
    `INSERT INTO map_lists(company_id, name, created_by_user_id) VALUES($1,$2,$3)
     ON CONFLICT(company_id, name) DO UPDATE SET updated_at = now()
     RETURNING id`,
    [companyId, name, createdByUserId]
  );
  return rows[0].id;
}

function normalizeMapStatus(status) {
  const s = String(status || "lead").toLowerCase();
  return mapStatusOptions().includes(s) ? s : "lead";
}

function mapPinPayload(pin) {
  return {
    pin_id: pin.id,
    status: pin.status || null,
    list_id: pin.list_id || null,
    contact_id: pin.contact_id || null,
    address: pin.address || "",
    latitude: pin.latitude,
    longitude: pin.longitude,
    source: pin.source || "manual",
    last_visit_at: pin.last_visit_at || null,
    last_knock_at: pin.last_knock_at || null,
    knock_count: Number(pin.knock_count || 0),
    visit_count: Number(pin.visit_count || 0)
  };
}

async function emitMapPinEvents(companyId, before, after, source, actorUserId = null, payload = {}) {
  if (!after?.id) return;
  const base = { ...mapPinPayload(after), ...payload };
  if (!before) {
    await emitAutomationEvent({ companyId, eventType: "map.pin_created", subjectType: "map_pin", subjectId: after.id, actorUserId, source, dedupeKey: `map.pin_created:${after.id}`, payload: base });
    await syncAutomationSchedulesForMapPin(companyId, after, "status_changed");
    return;
  }
  const changed = diffFields(before, after, ["latitude", "longitude", "name", "address", "notes", "status", "phone", "email", "contact_id", "list_id"]);
  if (!changed.length) return;
  await emitAutomationEvent({ companyId, eventType: "map.pin_updated", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: { ...base, changed_fields: changed } });
  const changedNames = new Set(changed.map((c) => c.field));
  if (changedNames.has("status")) {
    await emitAutomationEvent({ companyId, eventType: "map.pin_status_changed", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: { ...base, changed_fields: changed.filter((c) => c.field === "status"), old_status: before.status, new_status: after.status } });
    const statusEvents = { lead: ["map.pin_converted_to_lead", "canvass.lead_created"], won: ["map.pin_marked_won", "canvass.sale_recorded"], lost: ["map.pin_marked_lost", "canvass.not_interested"], reloop: ["map.pin_marked_reloop", "canvass.reloop_created"], later: ["map.pin_marked_later", "canvass.no_answer"] };
    for (const eventType of statusEvents[after.status] || []) await emitAutomationEvent({ companyId, eventType, subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: base });
    await syncAutomationSchedulesForMapPin(companyId, after, "status_changed");
  }
  if (changedNames.has("list_id")) {
    await emitAutomationEvent({ companyId, eventType: "map.pin_list_changed", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: { ...base, old_list_id: before.list_id || null, new_list_id: after.list_id || null } });
    if (after.list_id) await emitAutomationEvent({ companyId, eventType: "map.pin_added_to_list", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: base });
    if (before.list_id) await emitAutomationEvent({ companyId, eventType: "map.pin_removed_from_list", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: { ...base, removed_list_id: before.list_id } });
  }
  if (changedNames.has("contact_id")) {
    await emitAutomationEvent({ companyId, eventType: after.contact_id ? "map.pin_contact_linked" : "map.pin_contact_unlinked", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: base });
  }
  if (changedNames.has("address")) await emitAutomationEvent({ companyId, eventType: "map.pin_address_changed", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: base });
  if (changedNames.has("latitude") || changedNames.has("longitude")) await emitAutomationEvent({ companyId, eventType: "map.pin_location_changed", subjectType: "map_pin", subjectId: after.id, actorUserId, source, payload: base });
}

async function insertMapActivity(run, node, type, config) {
  const context = await buildRunContext(run);
  const pin = await resolveMapPin(run.company_id, config.pin_id || run.subject_id, context);
  const note = resolveTemplate(config.note || config.body || "", context);
  const { rows } = await ctx.pool.query(
    `INSERT INTO map_pin_activities(company_id, pin_id, user_id, activity_type, old_status, new_status, note, metadata, source, automation_run_id, automation_node_id)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'automation',$9,$10) RETURNING *`,
    [run.company_id, pin.id, run.manual_started_by_user_id || null, type, pin.status || null, config.outcome_status || null, note || null, JSON.stringify({}), run.id, node.id]
  );
  let updated = pin;
  if (type === "visit" || type === "knock") {
    const update = type === "knock"
      ? `last_knock_at = now(), knock_count = knock_count + 1`
      : `last_visit_at = now(), visit_count = visit_count + 1`;
    updated = (await ctx.pool.query(`UPDATE map_pins SET ${update}, updated_at = now() WHERE id = $1 RETURNING *`, [pin.id])).rows[0];
    await syncAutomationSchedulesForMapPin(run.company_id, updated, type === "knock" ? "last_knock" : "last_visit");
  }
  const eventType = type === "knock" ? "map.pin_knocked" : type === "visit" ? "map.pin_visited" : "map.pin_note_added";
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: "map_pin", subjectId: pin.id, source: "automation", payload: automationPayload(run, node, { ...mapPinPayload(updated), activity_id: rows[0].id, note }) });
  if (type === "knock") {
    await emitAutomationEvent({ companyId: run.company_id, eventType: "canvass.knock_recorded", subjectType: "map_pin", subjectId: pin.id, source: "automation", payload: automationPayload(run, node, { ...mapPinPayload(updated), activity_id: rows[0].id, note }) });
    if (config.outcome_status) await emitAutomationEvent({ companyId: run.company_id, eventType: "canvass.outcome_recorded", subjectType: "map_pin", subjectId: pin.id, source: "automation", payload: automationPayload(run, node, { ...mapPinPayload(updated), outcome_status: config.outcome_status }) });
  }
  return { pin_id: pin.id, activity_id: rows[0].id, activity_type: type };
}

async function resolveRoute(companyId, routeId) {
  if (!routeId) throw new Error("route_required");
  const route = (await ctx.pool.query(`SELECT * FROM field_routes WHERE id::text = $1 AND company_id = $2`, [routeId, companyId])).rows[0];
  if (!route) throw new Error("route_not_found");
  return route;
}

async function resolveRouteStop(companyId, stopId) {
  if (!stopId) throw new Error("route_stop_required");
  const stop = (await ctx.pool.query(`SELECT * FROM field_route_stops WHERE id::text = $1 AND company_id = $2`, [stopId, companyId])).rows[0];
  if (!stop) throw new Error("route_stop_not_found");
  return stop;
}

async function insertRouteStop(run, node, route, data) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:route_stop_id`);
  if (existing) return { route_id: route.id, route_stop_id: existing, reused: true };
  const order = (await ctx.pool.query(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM field_route_stops WHERE route_id = $1`, [route.id])).rows[0]?.next_order || 0;
  const { rows } = await ctx.pool.query(
    `INSERT INTO field_route_stops(id, route_id, company_id, pin_id, contact_id, job_id, latitude, longitude, address, sort_order)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT DO NOTHING
     RETURNING *`,
    [randomUUID(), route.id, run.company_id, data.pin_id || null, data.contact_id || null, data.job_id || null, numOrNull(data.latitude), numOrNull(data.longitude), data.address || "", order]
  );
  const stop = rows[0] || (await ctx.pool.query(`SELECT * FROM field_route_stops WHERE route_id = $1 AND (($2::text IS NOT NULL AND pin_id = $2) OR ($3::text IS NOT NULL AND contact_id = $3) OR ($4::uuid IS NOT NULL AND job_id = $4)) LIMIT 1`, [route.id, data.pin_id || null, data.contact_id || null, data.job_id || null])).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:route_stop_id`, stop.id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "route.stop_added", subjectType: "route_stop", subjectId: stop.id, source: "automation", payload: automationPayload(run, node, routeStopPayload(stop)) });
  return { route_id: route.id, route_stop_id: stop.id };
}

async function updateRouteStopStatus(run, node, stopId, status, notes) {
  const stop = await resolveRouteStop(run.company_id, stopId);
  const { rows } = await ctx.pool.query(`UPDATE field_route_stops SET status = $3, notes = COALESCE($4, notes), completed_at = CASE WHEN $3 IN ('completed','skipped') THEN COALESCE(completed_at, now()) ELSE completed_at END, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [stop.id, run.company_id, status, notes || null]);
  const eventType = status === "completed" ? "route.stop_completed" : "route.stop_skipped";
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: "route_stop", subjectId: stop.id, source: "automation", payload: automationPayload(run, node, routeStopPayload(rows[0])) });
  const remaining = await ctx.pool.query(`SELECT 1 FROM field_route_stops WHERE route_id = $1 AND status NOT IN ('completed','skipped') LIMIT 1`, [stop.route_id]);
  if (!remaining.rowCount) await emitAutomationEvent({ companyId: run.company_id, eventType: "route.all_stops_completed", subjectType: "route", subjectId: stop.route_id, source: "automation", payload: automationPayload(run, node, { route_id: stop.route_id }) });
  return { route_id: stop.route_id, route_stop_id: stop.id, status };
}

function routeStopPayload(stop) {
  return { route_id: stop.route_id, route_stop_id: stop.id, pin_id: stop.pin_id || null, contact_id: stop.contact_id || null, job_id: stop.job_id || null, status: stop.status, sort_order: stop.sort_order, latitude: stop.latitude, longitude: stop.longitude, address: stop.address || "" };
}

async function emitRouteEvent(run, node, eventType, route, extra = {}) {
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: "route", subjectId: route.id, source: "automation", payload: automationPayload(run, node, { route_id: route.id, name: route.name, status: route.status, assigned_user_id: route.assigned_user_id || null, scheduled_date: route.scheduled_date || null, ...extra }) });
}

function optimizeStops(stops) {
  const usable = stops.filter((s) => Number.isFinite(Number(s.latitude)) && Number.isFinite(Number(s.longitude)));
  const missing = stops.filter((s) => !usable.includes(s));
  if (usable.length < 3) return [...usable, ...missing];
  const remaining = [...usable];
  const ordered = [remaining.shift()];
  while (remaining.length) {
    const last = ordered[ordered.length - 1];
    let bestIndex = 0;
    let bestDistance = Infinity;
    for (let i = 0; i < remaining.length; i++) {
      const d = haversineMiles(last.latitude, last.longitude, remaining[i].latitude, remaining[i].longitude);
      if (d < bestDistance) { bestDistance = d; bestIndex = i; }
    }
    ordered.push(remaining.splice(bestIndex, 1)[0]);
  }
  let improved = true;
  while (improved) {
    improved = false;
    for (let i = 1; i < ordered.length - 2; i++) {
      for (let k = i + 1; k < ordered.length - 1; k++) {
        const current = segmentDistance(ordered[i - 1], ordered[i]) + segmentDistance(ordered[k], ordered[k + 1]);
        const swapped = segmentDistance(ordered[i - 1], ordered[k]) + segmentDistance(ordered[i], ordered[k + 1]);
        if (swapped < current) {
          ordered.splice(i, k - i + 1, ...ordered.slice(i, k + 1).reverse());
          improved = true;
        }
      }
    }
  }
  return [...ordered, ...missing];
}

function routeDistanceMiles(stops) {
  return stops.slice(1).reduce((sum, stop, i) => sum + segmentDistance(stops[i], stop), 0);
}

function segmentDistance(a, b) {
  return haversineMiles(a.latitude, a.longitude, b.latitude, b.longitude);
}

function haversineMiles(lat1, lon1, lat2, lon2) {
  const toRad = (n) => Number(n) * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 3958.8 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function resolveEmployee(companyId, employeeId, options = {}) {
  if (!employeeId) throw new Error("employee_required");
  const employee = (await ctx.pool.query(`SELECT id, email, role, display_name, deleted_at FROM users WHERE id::text = $1 AND company_id = $2`, [employeeId, companyId])).rows[0];
  if (!employee) throw new Error("employee_not_found");
  if (employee.deleted_at && !options.allowInactive) throw new Error("employee_inactive");
  return employee;
}

async function resolveActiveCompanyUser(companyId, userId) {
  const employee = await resolveEmployee(companyId, userId);
  return employee.id;
}

async function assertNotLastEmployer(companyId, employeeId) {
  const count = (await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM users WHERE company_id = $1 AND role = 'employer' AND deleted_at IS NULL AND id <> $2`, [companyId, employeeId])).rows[0]?.count || 0;
  if (Number(count) <= 0) throw new Error("cannot_mutate_last_employer");
}

async function emitEmployeeEvent(run, node, eventType, employee, extra = {}) {
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: "employee", subjectId: employee.id, source: "automation", payload: automationPayload(run, node, { employee_id: employee.id, role: employee.role, active: !employee.deleted_at, name: employee.display_name || employee.email, ...extra }) });
}

async function resolveTimeEntry(companyId, entryId) {
  if (!entryId) throw new Error("time_entry_required");
  const entry = (await ctx.pool.query(`SELECT * FROM time_clock_entries WHERE id = $1 AND company_id = $2`, [entryId, companyId])).rows[0];
  if (!entry) throw new Error("time_entry_not_found");
  return entry;
}

async function resolveMeasurement(companyId, measurementId) {
  if (!measurementId) throw new Error("measurement_required");
  const measurement = (await ctx.pool.query(`SELECT m.* FROM measurements m JOIN users u ON u.id = m.user_id WHERE m.id = $1 AND u.company_id = $2`, [measurementId, companyId])).rows[0];
  if (!measurement) throw new Error("measurement_not_found");
  return measurement;
}

function measurementPayload(m) {
  const points = Array.isArray(m.points) ? m.points : [];
  return { measurement_id: m.id, name: m.name, units: m.units, linked_contact_ids: m.linked_contact_ids || [], distance: pathDistance(points), area: polygonAreaApprox(points), type: points.length >= 3 ? "area" : "distance" };
}

function pathDistance(points) {
  if (!Array.isArray(points) || points.length < 2) return 0;
  return points.slice(1).reduce((sum, p, i) => sum + haversineMiles(points[i].lat, points[i].lng, p.lat, p.lng), 0);
}

function polygonAreaApprox(points) {
  if (!Array.isArray(points) || points.length < 3) return 0;
  const meanLat = points.reduce((sum, p) => sum + Number(p.lat || 0), 0) / points.length;
  const meters = points.map((p) => ({ x: Number(p.lng || 0) * 111320 * Math.cos(meanLat * Math.PI / 180), y: Number(p.lat || 0) * 110540 }));
  let area = 0;
  for (let i = 0; i < meters.length; i++) {
    const j = (i + 1) % meters.length;
    area += meters[i].x * meters[j].y - meters[j].x * meters[i].y;
  }
  return Math.abs(area / 2);
}

function intOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.round(n) : null;
}

function numOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

async function getRunVariable(runId, name) {
  return (await ctx.pool.query(`SELECT value FROM automation_variables WHERE run_id = $1 AND name = $2`, [runId, name])).rows[0]?.value || null;
}

async function setRunVariable(runId, name, value) {
  await ctx.pool.query(
    `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
     ON CONFLICT(run_id, name) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [runId, name, JSON.stringify(value)]
  );
}

function automationPayload(run, node, extra = {}) {
  return {
    ...extra,
    origin_run_id: run.id,
    origin_node_id: node?.id || null,
    root_run_id: run.root_run_id || run.id,
    automation_event_depth: Number(extra.automation_event_depth || 0) + 1
  };
}

function contactChangedFields(before, after, fields) {
  const changed = [];
  for (const field of fields) {
    const oldValue = before?.[field] ?? null;
    const newValue = after?.[field] ?? null;
    if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) changed.push({ field, old_value: oldValue, new_value: newValue });
  }
  return changed;
}

async function emitContactChangeEvents(companyId, contactId, source, actorUserId, changedFields, payload = {}) {
  if (!changedFields.length) return;
  await emitAutomationEvent({ companyId, eventType: "contact.updated", subjectType: "contact", subjectId: contactId, actorUserId, source, payload: { ...payload, changed_fields: changedFields } });
  await emitAutomationEvent({ companyId, eventType: "contact.field_changed", subjectType: "contact", subjectId: contactId, actorUserId, source, payload: { ...payload, changed_fields: changedFields } });
  for (const item of changedFields) {
    const eventType = contactFieldEventType(item.field);
    if (eventType) await emitAutomationEvent({ companyId, eventType, subjectType: "contact", subjectId: contactId, actorUserId, source, payload: { ...payload, changed_fields: [item], field: item.field, old_value: item.old_value, new_value: item.new_value } });
  }
}

function contactFieldEventType(field) {
  if (["name", "phone", "email", "address", "job_type", "source"].includes(field)) return `contact.${field}_changed`;
  if (field === "value_cents") return "contact.value_changed";
  if (["u1", "u2", "u3", "u4", "u5"].includes(field)) return `contact.${field}_changed`;
  if (field === "lat" || field === "lng") return "contact.location_changed";
  return null;
}

async function emitContactTagEvents(run, node, contactId, result) {
  const payload = automationPayload(run, node, { contact_id: contactId, tags: result.next, added_tags: result.added, removed_tags: result.removed });
  if (result.added.length) await emitAutomationEvent({ companyId: run.company_id, eventType: "contact.tag_added", subjectType: "contact", subjectId: contactId, source: "automation", payload });
  if (result.removed.length) await emitAutomationEvent({ companyId: run.company_id, eventType: "contact.tag_removed", subjectType: "contact", subjectId: contactId, source: "automation", payload });
  if (result.added.length || result.removed.length) await emitAutomationEvent({ companyId: run.company_id, eventType: "contact.tags_changed", subjectType: "contact", subjectId: contactId, source: "automation", payload });
}

async function executePipelineMoveStage(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const stageId = resolveTemplate(config.stage_id || "", context);
  const stage = await ctx.pool.query(`SELECT id FROM stages WHERE id = $1 AND company_id = $2`, [stageId, run.company_id]);
  if (!stage.rowCount) throw new Error("stage_not_found");
  const existing = (await ctx.pool.query(`SELECT * FROM opportunities WHERE company_id = $1 AND contact_id = $2 LIMIT 1`, [run.company_id, contactId])).rows[0];
  if (!existing && (config.if_missing || "fail") !== "create") throw new Error("opportunity_not_found");
  const id = existing?.id || config.opportunity_id || randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO opportunities(id, user_id, company_id, contact_id, state, stage_id)
     VALUES($1, (SELECT owner_user_id FROM companies WHERE id = $2), $2, $3, 'stage', $4)
     ON CONFLICT(user_id, contact_id) DO UPDATE SET state = 'stage', stage_id = EXCLUDED.stage_id, updated_at = now()
     RETURNING id, stage_id`,
    [id, run.company_id, contactId, stageId]
  );
  await emitPipelineStageEvents(run.company_id, rows[0].id, contactId, existing, rows[0], "automation", automationPayload(run, node, {}));
  return { opportunity_id: rows[0].id, previous_stage_id: existing?.stage_id || null, stage_id: rows[0].stage_id };
}

async function executePipelineCreateOpportunity(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const existing = (await ctx.pool.query(`SELECT * FROM opportunities WHERE company_id = $1 AND contact_id = $2 LIMIT 1`, [run.company_id, contactId])).rows[0];
  if (existing) {
    if ((config.if_exists || "reuse") === "fail") throw new Error("opportunity_exists");
    if (config.if_exists === "move") return executePipelineMoveStage(run, node, { ...config, if_missing: "create" });
    return { opportunity_id: existing.id, contact_id: contactId, reused: true, stage_id: existing.stage_id };
  }
  const stageId = resolveTemplate(config.stage_id || "", context);
  if (!stageId) throw new Error("stage_id_required");
  const stage = await ctx.pool.query(`SELECT id FROM stages WHERE id = $1 AND company_id = $2`, [stageId, run.company_id]);
  if (!stage.rowCount) throw new Error("stage_not_found");
  const owner = await resolveCompanyUser(run.company_id, "");
  const id = randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO opportunities(id, user_id, company_id, contact_id, state, stage_id) VALUES($1,$2,$3,$4,'stage',$5) RETURNING *`,
    [id, owner, run.company_id, contactId, stageId]
  );
  await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.opportunity_created", subjectType: "opportunity", subjectId: id, source: "automation", dedupeKey: `pipeline.opportunity_created:${id}`, payload: automationPayload(run, node, { opportunity_id: id, contact_id: contactId, stage_id: stageId }) });
  await emitPipelineStageEvents(run.company_id, id, contactId, null, rows[0], "automation", automationPayload(run, node, {}));
  return { opportunity_id: id, contact_id: contactId, stage_id: stageId };
}

async function executePipelineRemoveOpportunity(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const opp = await resolveOpportunity(run.company_id, contactId, config.opportunity_id);
  await ctx.pool.query(`DELETE FROM opportunities WHERE id = $1 AND company_id = $2`, [opp.id, run.company_id]);
  const payload = automationPayload(run, node, { opportunity_id: opp.id, contact_id: contactId, stage_id: opp.stage_id, previous_stage_id: opp.stage_id });
  await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.opportunity_removed", subjectType: "opportunity", subjectId: opp.id, source: "automation", payload });
  if (opp.stage_id) await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.stage_exited", subjectType: "opportunity", subjectId: opp.id, source: "automation", payload });
  return { opportunity_id: opp.id, removed: true };
}

async function executePipelineMarkWon(run, node, config) {
  return updateOpportunityState(run, node, config, "won", "pipeline.won");
}

async function executePipelineMarkLost(run, node, config) {
  return updateOpportunityState(run, node, config, "lost", "pipeline.lost");
}

async function executePipelineReopen(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const stageId = resolveTemplate(config.stage_id || "", context);
  if (!stageId) throw new Error("stage_id_required");
  const opp = await resolveOpportunity(run.company_id, contactId, config.opportunity_id);
  const { rows } = await ctx.pool.query(`UPDATE opportunities SET state = 'stage', stage_id = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [opp.id, run.company_id, stageId]);
  const payload = automationPayload(run, node, { opportunity_id: opp.id, contact_id: contactId, previous_state: opp.state, stage_id: stageId, previous_stage_id: opp.stage_id });
  await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.reopened", subjectType: "opportunity", subjectId: opp.id, source: "automation", payload });
  await emitPipelineStageEvents(run.company_id, opp.id, contactId, opp, rows[0], "automation", payload);
  return { opportunity_id: opp.id, stage_id: stageId, previous_state: opp.state };
}

async function executePipelineSetValue(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const value = intOrNull(resolveTemplate(config.value_cents ?? config.value ?? "", context));
  if (value == null) throw new Error("value_required");
  const before = (await ctx.pool.query(`SELECT * FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, run.company_id])).rows[0];
  const { rows } = await ctx.pool.query(`UPDATE contacts SET value_cents = $3, updated_at = now() WHERE id::text = $1 AND company_id = $2 RETURNING *`, [contactId, run.company_id, value]);
  const changed = contactChangedFields(before, rows[0], ["value_cents"]);
  await emitContactChangeEvents(run.company_id, contactId, "automation", null, changed, automationPayload(run, node, { contact_id: contactId }));
  const opp = await resolveOpportunity(run.company_id, contactId, config.opportunity_id).catch(() => null);
  if (opp) await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.value_changed", subjectType: "opportunity", subjectId: opp.id, source: "automation", payload: automationPayload(run, node, { opportunity_id: opp.id, contact_id: contactId, value_cents: value }) });
  return { contact_id: contactId, value_cents: value };
}

async function updateOpportunityState(run, node, config, state, eventType) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const opp = await resolveOpportunity(run.company_id, contactId, config.opportunity_id);
  const { rows } = await ctx.pool.query(`UPDATE opportunities SET state = $3, stage_id = NULL, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [opp.id, run.company_id, state]);
  const payload = automationPayload(run, node, { opportunity_id: opp.id, contact_id: contactId, previous_state: opp.state, previous_stage_id: opp.stage_id, state, reason: config.reason || null });
  if (opp.stage_id) await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.stage_exited", subjectType: "opportunity", subjectId: opp.id, source: "automation", payload });
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: "opportunity", subjectId: opp.id, source: "automation", payload });
  return { opportunity_id: opp.id, state: rows[0].state, previous_stage_id: opp.stage_id };
}

async function resolveOpportunity(companyId, contactId, opportunityId) {
  const row = opportunityId
    ? (await ctx.pool.query(`SELECT * FROM opportunities WHERE id = $1 AND company_id = $2`, [opportunityId, companyId])).rows[0]
    : (await ctx.pool.query(`SELECT * FROM opportunities WHERE company_id = $1 AND contact_id = $2 LIMIT 1`, [companyId, contactId])).rows[0];
  if (!row) throw new Error("opportunity_not_found");
  return row;
}

async function emitPipelineStageEvents(companyId, opportunityId, contactId, before, after, source, payload = {}) {
  const oldStage = before?.stage_id || null;
  const newStage = after?.stage_id || null;
  if (oldStage && oldStage !== newStage) await emitAutomationEvent({ companyId, eventType: "pipeline.stage_exited", subjectType: "opportunity", subjectId: opportunityId, source, payload: { ...payload, opportunity_id: opportunityId, contact_id: contactId, previous_stage_id: oldStage, stage_id: oldStage, new_stage_id: newStage } });
  if (newStage && oldStage !== newStage) await emitAutomationEvent({ companyId, eventType: "pipeline.stage_entered", subjectType: "opportunity", subjectId: opportunityId, source, payload: { ...payload, opportunity_id: opportunityId, contact_id: contactId, previous_stage_id: oldStage, stage_id: newStage, new_stage_id: newStage } });
  if (oldStage !== newStage) {
    await emitAutomationEvent({ companyId, eventType: "pipeline.stage_changed", subjectType: "opportunity", subjectId: opportunityId, source, payload: { ...payload, opportunity_id: opportunityId, contact_id: contactId, previous_stage_id: oldStage, old_stage_id: oldStage, stage_id: newStage, new_stage_id: newStage } });
    await emitAutomationEvent({ companyId, eventType: "pipeline.opportunity_moved", subjectType: "opportunity", subjectId: opportunityId, source, payload: { ...payload, opportunity_id: opportunityId, contact_id: contactId, previous_stage_id: oldStage, stage_id: newStage } });
  }
}

async function executePipelineCreateReminder(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const opp = await resolveOpportunity(run.company_id, contactId, config.opportunity_id).catch(() => null);
  const owner = await resolveCompanyUser(run.company_id, config.assigned_user_id || "");
  const remindAt = resolveTemplate(config.remind_at || "", context);
  if (!remindAt) throw new Error("remind_at_required");
  const note = resolveTemplate(config.note || config.title || "Automation reminder", context);
  const { rows } = await ctx.pool.query(
    `INSERT INTO stage_reminders(user_id, contact_id, opportunity_id, remind_at, note) VALUES($1,$2,$3,$4::timestamptz,$5) RETURNING *`,
    [owner, contactId, opp?.id || null, remindAt, note]
  );
  await emitAutomationEvent({ companyId: run.company_id, eventType: "pipeline.reminder_created", subjectType: opp ? "opportunity" : "contact", subjectId: opp?.id || contactId, source: "automation", payload: automationPayload(run, node, { reminder_id: rows[0].id, contact_id: contactId, opportunity_id: opp?.id || null }) });
  return { reminder_id: rows[0].id, contact_id: contactId, opportunity_id: opp?.id || null };
}

async function executePipelineCompleteReminder(run, node, config) {
  return updateReminderArchived(run, node, config, "pipeline.reminder_completed");
}

async function executePipelineArchiveReminder(run, node, config) {
  return updateReminderArchived(run, node, config, "pipeline.reminder_archived");
}

async function updateReminderArchived(run, node, config, eventType) {
  const context = await buildRunContext(run);
  const reminderId = resolveTemplate(config.reminder_id || "", context);
  if (!reminderId) throw new Error("reminder_id_required");
  const { rows } = await ctx.pool.query(
    `UPDATE stage_reminders sr SET archived = true, updated_at = now()
      FROM users u
      WHERE sr.id = $1 AND sr.user_id = u.id AND u.company_id = $2
      RETURNING sr.*`,
    [reminderId, run.company_id]
  );
  if (!rows.length) throw new Error("reminder_not_found");
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: rows[0].opportunity_id ? "opportunity" : "contact", subjectId: rows[0].opportunity_id || rows[0].contact_id, source: "automation", payload: automationPayload(run, node, { reminder_id: reminderId, contact_id: rows[0].contact_id, opportunity_id: rows[0].opportunity_id }) });
  return { reminder_id: reminderId, archived: true };
}

async function executeTaskCreate(run, node, config) {
  const existingId = await getRunVariable(run.id, `idempotency:${node.id}:task_id`);
  if (existingId) {
    const existing = await loadTaskContext(run.company_id, existingId);
    if (existing?.exists) return { task_id: existingId, reused: true };
  }
  const context = await buildRunContext(run);
  const title = resolveTemplate(config.title || "Automation task", context);
  const assignee = await resolveCompanyUser(run.company_id, resolveTemplate(config.assigned_user_id || "", context));
  const dueDate = config.due_date || config.due_at ? resolveDateExpression(config.due_date || config.due_at, context) : null;
  const due = dueDate?.toISOString() || null;
  const id = randomUUID();
  const subtasks = normalizeTags(resolveConfig(config.subtasks || [], context)).map((title) => ({ title, completed: false }));
  const { rows } = await ctx.pool.query(
    `INSERT INTO todo_tasks(id, user_id, title, due_date, reminders, subtasks, completed, color_hex)
     VALUES($1,$2,$3,$4::timestamptz,'[]'::jsonb,$5::jsonb,false,$6) RETURNING *`,
    [id, assignee, title, due, JSON.stringify(subtasks), config.color_hex || "#3478F6"]
  );
  await setRunVariable(run.id, `idempotency:${node.id}:task_id`, id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "task.created", subjectType: "task", subjectId: id, source: "automation", dedupeKey: `task.created:${id}`, payload: automationPayload(run, node, { task_id: id, title, due_date: due }) });
  await syncAutomationSchedulesForTask(run.company_id, rows[0]);
  return { task_id: id, due_at: rows[0].due_date, title: rows[0].title };
}

async function executeTaskUpdate(run, node, config) {
  const context = await buildRunContext(run);
  const task = await resolveTask(run.company_id, run.subject_id, config.task_id, context);
  const updates = {};
  if (config.title != null) updates.title = resolveTemplate(config.title, context);
  if (config.due_date != null) updates.due_date = resolveDateExpression(config.due_date, context)?.toISOString() || null;
  if (config.completed != null) updates.completed = !!config.completed;
  if (config.assigned_user_id != null) updates.user_id = await resolveCompanyUser(run.company_id, resolveTemplate(config.assigned_user_id, context));
  return updateTaskRow(run, node, task, updates);
}
async function executeTaskComplete(run, node, config) { return executeTaskUpdate(run, node, { ...config, completed: true }); }
async function executeTaskReopen(run, node, config) { return executeTaskUpdate(run, node, { ...config, completed: false }); }
async function executeTaskReschedule(run, node, config) { return executeTaskUpdate(run, node, { ...config, due_date: config.due_date }); }
async function executeTaskAssign(run, node, config) { return executeTaskUpdate(run, node, { ...config, assigned_user_id: config.assigned_user_id || config.user_id }); }
async function executeTaskUnassign(run, node, config) { return executeTaskUpdate(run, node, { ...config, assigned_user_id: "" }); }

async function executeTaskDelete(run, node, config) {
  const context = await buildRunContext(run);
  const task = await resolveTask(run.company_id, run.subject_id, config.task_id, context);
  await ctx.pool.query(`DELETE FROM todo_tasks WHERE id = $1`, [task.id]);
  await cancelScheduledForSubject(run.company_id, "task", task.id, ["task.due", "task.overdue"]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "task.deleted", subjectType: "task", subjectId: task.id, source: "automation", payload: automationPayload(run, node, { task_id: task.id, title: task.title }) });
  return { task_id: task.id, deleted: true };
}

async function executeTaskAddSubtask(run, node, config) {
  const context = await buildRunContext(run);
  const task = await resolveTask(run.company_id, run.subject_id, config.task_id, context);
  const title = resolveTemplate(config.title || "", context).trim();
  if (!title) throw new Error("subtask_title_required");
  const subtasks = jsonArray(task.subtasks);
  subtasks.push({ title, completed: false });
  return updateTaskRow(run, node, task, { subtasks });
}

async function executeTaskCompleteSubtask(run, node, config) {
  const context = await buildRunContext(run);
  const task = await resolveTask(run.company_id, run.subject_id, config.task_id, context);
  const title = resolveTemplate(config.title || "", context).trim().toLowerCase();
  const subtasks = jsonArray(task.subtasks).map((s) => (String(s.title || "").toLowerCase() === title ? { ...s, completed: true } : s));
  return updateTaskRow(run, node, task, { subtasks });
}

async function executeTaskDeleteSubtask(run, node, config) {
  const context = await buildRunContext(run);
  const task = await resolveTask(run.company_id, run.subject_id, config.task_id, context);
  const title = resolveTemplate(config.title || "", context).trim().toLowerCase();
  const subtasks = jsonArray(task.subtasks).filter((s) => String(s.title || "").toLowerCase() !== title);
  return updateTaskRow(run, node, task, { subtasks });
}

async function resolveTask(companyId, subjectId, explicitId, context) {
  const taskId = resolveTemplate(explicitId || context.task?.id || subjectId || "", context);
  const task = (await ctx.pool.query(`SELECT tt.* FROM todo_tasks tt JOIN users u ON u.id = tt.user_id WHERE tt.id = $1 AND u.company_id = $2`, [taskId, companyId])).rows[0];
  if (!task) throw new Error("task_not_found");
  return task;
}

async function updateTaskRow(run, node, before, updates) {
  const cols = Object.keys(updates);
  if (!cols.length) return { task_id: before.id, updated: [] };
  const sets = cols.map((key, i) => `${key} = $${i + 3}${key === "subtasks" ? "::jsonb" : ""}`);
  const values = cols.map((key) => key === "subtasks" ? JSON.stringify(updates[key]) : updates[key]);
  const { rows } = await ctx.pool.query(`UPDATE todo_tasks SET ${sets.join(", ")}, completed_at = CASE WHEN completed = true AND completed_at IS NULL THEN now() WHEN completed = false THEN NULL ELSE completed_at END, updated_at = now() WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2) RETURNING *`, [before.id, run.company_id, ...values]);
  const after = rows[0];
  await emitTaskMutationEvents(run.company_id, before, after, "automation", null, automationPayload(run, node, { task_id: after.id }));
  await syncAutomationSchedulesForTask(run.company_id, after);
  return { task_id: after.id, updated: cols, due_at: after.due_date };
}

async function emitTaskMutationEvents(companyId, before, after, source, actorUserId, payload = {}) {
  const taskId = after?.id || before?.id;
  if (!before) {
    await emitAutomationEvent({ companyId, eventType: "task.created", subjectType: "task", subjectId: taskId, actorUserId, source, dedupeKey: `task.created:${taskId}`, payload: { ...payload, task_id: taskId, title: after.title, due_date: after.due_date } });
    return;
  }
  const fields = ["title", "due_date", "completed", "user_id", "subtasks"];
  const changed = fields.map((field) => ({ field, old_value: before[field] ?? null, new_value: after[field] ?? null })).filter((f) => JSON.stringify(f.old_value) !== JSON.stringify(f.new_value));
  if (!changed.length) return;
  await emitAutomationEvent({ companyId, eventType: "task.updated", subjectType: "task", subjectId: taskId, actorUserId, source, payload: { ...payload, task_id: taskId, changed_fields: changed } });
  if (changed.some((f) => f.field === "title")) await emitAutomationEvent({ companyId, eventType: "task.title_changed", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
  if (changed.some((f) => f.field === "due_date")) {
    await emitAutomationEvent({ companyId, eventType: "task.due_changed", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
    await emitAutomationEvent({ companyId, eventType: "task.rescheduled", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
  }
  if (!before.completed && after.completed) await emitAutomationEvent({ companyId, eventType: "task.completed", subjectType: "task", subjectId: taskId, actorUserId, source, dedupeKey: `task.completed:${taskId}:${after.completed_at || "completed"}`, payload: { ...payload, completed_at: after.completed_at } });
  if (before.completed && !after.completed) await emitAutomationEvent({ companyId, eventType: "task.reopened", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
  if (before.user_id !== after.user_id) await emitAutomationEvent({ companyId, eventType: before.user_id ? "task.reassigned" : "task.assigned", subjectType: "task", subjectId: taskId, actorUserId, source, payload: { ...payload, previous_user_id: before.user_id, user_id: after.user_id } });
  await emitSubtaskEvents(companyId, taskId, before, after, source, actorUserId, payload);
}

async function emitSubtaskEvents(companyId, taskId, before, after, source, actorUserId, payload) {
  const oldTasks = jsonArray(before.subtasks);
  const newTasks = jsonArray(after.subtasks);
  if (newTasks.length > oldTasks.length) await emitAutomationEvent({ companyId, eventType: "task.subtask_added", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
  const oldCompleted = oldTasks.filter((s) => s.completed).length;
  const newCompleted = newTasks.filter((s) => s.completed).length;
  if (newCompleted > oldCompleted) await emitAutomationEvent({ companyId, eventType: "task.subtask_completed", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
  if (oldTasks.length > 0 && oldCompleted < oldTasks.length && newTasks.length > 0 && newCompleted === newTasks.length) await emitAutomationEvent({ companyId, eventType: "task.all_subtasks_completed", subjectType: "task", subjectId: taskId, actorUserId, source, payload });
}

async function executeRoutineCreate(run, node, config) {
  const existingId = await getRunVariable(run.id, `idempotency:${node.id}:routine_id`);
  if (existingId) return { routine_id: existingId, reused: true };
  const context = await buildRunContext(run);
  const owner = await resolveCompanyUser(run.company_id, config.assigned_user_id || "");
  const id = randomUUID();
  const title = resolveTemplate(config.title || "Automation routine", context);
  const time = resolveDateExpression(config.time || "now", context)?.toISOString() || null;
  const weekdays = Array.isArray(config.weekdays) ? config.weekdays.map(Number) : [1, 2, 3, 4, 5];
  const { rows } = await ctx.pool.query(`INSERT INTO todo_routines(id, user_id, title, time, weekdays, reminders, enabled, color_hex) VALUES($1,$2,$3,$4::timestamptz,$5::jsonb,'[]'::jsonb,true,$6) RETURNING *`, [id, owner, title, time, JSON.stringify(weekdays), config.color_hex || "#3478F6"]);
  await setRunVariable(run.id, `idempotency:${node.id}:routine_id`, id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "routine.created", subjectType: "routine", subjectId: id, source: "automation", dedupeKey: `routine.created:${id}`, payload: automationPayload(run, node, { routine_id: id, title }) });
  await syncAutomationSchedulesForRoutine(run.company_id, rows[0]);
  return { routine_id: id };
}

async function executeRoutineUpdate(run, node, config) {
  const context = await buildRunContext(run);
  const routine = await resolveRoutine(run.company_id, run.subject_id, config.routine_id, context);
  const updates = {};
  if (config.title != null) updates.title = resolveTemplate(config.title, context);
  if (config.time != null) updates.time = resolveDateExpression(config.time, context)?.toISOString() || null;
  if (config.weekdays != null) updates.weekdays = Array.isArray(config.weekdays) ? config.weekdays.map(Number) : [];
  return updateRoutineRow(run, node, routine, updates);
}

async function executeRoutineMarkCompleted(run, node, config) {
  const context = await buildRunContext(run);
  const routine = await resolveRoutine(run.company_id, run.subject_id, config.routine_id, context);
  const dayKey = resolveTemplate(config.day_key || new Date().toISOString().slice(0, 10), context);
  await ctx.pool.query(`INSERT INTO todo_routine_done(user_id, routine_id, day_key) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, [routine.user_id, routine.id, dayKey]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "routine.completed", subjectType: "routine", subjectId: routine.id, source: "automation", dedupeKey: `routine.completed:${routine.id}:${dayKey}`, payload: automationPayload(run, node, { routine_id: routine.id, day_key: dayKey }) });
  return { routine_id: routine.id, day_key: dayKey };
}

async function executeRoutineEnd(run, node, config) {
  const context = await buildRunContext(run);
  const routine = await resolveRoutine(run.company_id, run.subject_id, config.routine_id, context);
  return updateRoutineRow(run, node, routine, { enabled: false });
}

async function resolveRoutine(companyId, subjectId, explicitId, context) {
  const routineId = resolveTemplate(explicitId || context.routine?.id || subjectId || "", context);
  const row = (await ctx.pool.query(`SELECT tr.* FROM todo_routines tr JOIN users u ON u.id = tr.user_id WHERE tr.id = $1 AND u.company_id = $2`, [routineId, companyId])).rows[0];
  if (!row) throw new Error("routine_not_found");
  return row;
}

async function updateRoutineRow(run, node, before, updates) {
  const cols = Object.keys(updates);
  const sets = cols.map((key, i) => `${key} = $${i + 3}${key === "weekdays" ? "::jsonb" : ""}`);
  const values = cols.map((key) => key === "weekdays" ? JSON.stringify(updates[key]) : updates[key]);
  const { rows } = await ctx.pool.query(`UPDATE todo_routines SET ${sets.join(", ")}, updated_at = now() WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2) RETURNING *`, [before.id, run.company_id, ...values]);
  const after = rows[0];
  await emitAutomationEvent({ companyId: run.company_id, eventType: "routine.updated", subjectType: "routine", subjectId: after.id, source: "automation", payload: automationPayload(run, node, { routine_id: after.id }) });
  if (before.enabled && !after.enabled) await emitAutomationEvent({ companyId: run.company_id, eventType: "routine.ended", subjectType: "routine", subjectId: after.id, source: "automation", payload: automationPayload(run, node, { routine_id: after.id }) });
  if (!before.enabled && after.enabled) await emitAutomationEvent({ companyId: run.company_id, eventType: "routine.reactivated", subjectType: "routine", subjectId: after.id, source: "automation", payload: automationPayload(run, node, { routine_id: after.id }) });
  await syncAutomationSchedulesForRoutine(run.company_id, after);
  return { routine_id: after.id, updated: cols };
}

async function executeCustomerReminderCreate(run, node, config) {
  const existingId = await getRunVariable(run.id, `idempotency:${node.id}:customer_reminder_id`);
  if (existingId) return { reminder_id: existingId, reused: true };
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config).catch(() => null);
  const contact = contactId ? await loadContactContext(run.company_id, contactId) : null;
  const owner = await resolveCompanyUser(run.company_id, config.assigned_user_id || "");
  const id = randomUUID();
  const due = resolveDateExpression(config.due_date || config.due_at || "", context)?.toISOString() || null;
  const title = resolveTemplate(config.title || "Customer reminder", context);
  const { rows } = await ctx.pool.query(`INSERT INTO todo_customer_reminders(id, user_id, title, contact_id, contact_name, phone, due_date, completed, color_hex) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz,false,$8) RETURNING *`, [id, owner, title, contactId, config.contact_name || contact?.name || "Customer", contact?.phone || null, due, config.color_hex || "#3478F6"]);
  await setRunVariable(run.id, `idempotency:${node.id}:customer_reminder_id`, id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "customer_reminder.created", subjectType: "customer_reminder", subjectId: id, source: "automation", dedupeKey: `customer_reminder.created:${id}`, payload: automationPayload(run, node, { reminder_id: id, contact_id: contactId, due_date: due }) });
  await syncAutomationSchedulesForCustomerReminder(run.company_id, rows[0]);
  return { reminder_id: id, due_at: due };
}

async function executeCustomerReminderComplete(run, node, config) { return updateCustomerReminder(run, node, config, { completed: true }); }
async function executeCustomerReminderReopen(run, node, config) { return updateCustomerReminder(run, node, config, { completed: false }); }
async function executeCustomerReminderReschedule(run, node, config) {
  const context = await buildRunContext(run);
  return updateCustomerReminder(run, node, config, { due_date: resolveDateExpression(config.due_date || config.due_at || "", context)?.toISOString() || null });
}
async function executeCustomerReminderDelete(run, node, config) {
  const context = await buildRunContext(run);
  const reminder = await resolveCustomerReminder(run.company_id, run.subject_id, config.reminder_id, context);
  await ctx.pool.query(`DELETE FROM todo_customer_reminders WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2)`, [reminder.id, run.company_id]);
  await cancelScheduledForSubject(run.company_id, "customer_reminder", reminder.id, ["customer_reminder.due", "customer_reminder.overdue"]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "customer_reminder.deleted", subjectType: "customer_reminder", subjectId: reminder.id, source: "automation", payload: automationPayload(run, node, { reminder_id: reminder.id }) });
  return { reminder_id: reminder.id, deleted: true };
}

async function updateCustomerReminder(run, node, config, updates) {
  const context = await buildRunContext(run);
  const before = await resolveCustomerReminder(run.company_id, run.subject_id, config.reminder_id, context);
  const cols = Object.keys(updates);
  const sets = cols.map((key, i) => `${key} = $${i + 3}`);
  const { rows } = await ctx.pool.query(`UPDATE todo_customer_reminders SET ${sets.join(", ")}, updated_at = now() WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2) RETURNING *`, [before.id, run.company_id, ...cols.map((k) => updates[k])]);
  const after = rows[0];
  const eventType = before.completed === false && after.completed ? "customer_reminder.completed" : before.completed && !after.completed ? "customer_reminder.reopened" : "customer_reminder.rescheduled";
  await emitAutomationEvent({ companyId: run.company_id, eventType, subjectType: "customer_reminder", subjectId: after.id, source: "automation", payload: automationPayload(run, node, { reminder_id: after.id, due_date: after.due_date }) });
  await syncAutomationSchedulesForCustomerReminder(run.company_id, after);
  return { reminder_id: after.id, due_at: after.due_date, completed: after.completed };
}

async function resolveCustomerReminder(companyId, subjectId, explicitId, context) {
  const reminderId = resolveTemplate(explicitId || context.customer_reminder?.id || subjectId || "", context);
  const row = (await ctx.pool.query(`SELECT cr.* FROM todo_customer_reminders cr JOIN users u ON u.id = cr.user_id WHERE cr.id = $1 AND u.company_id = $2`, [reminderId, companyId])).rows[0];
  if (!row) throw new Error("customer_reminder_not_found");
  return row;
}

async function resolveCompanyUser(companyId, userId) {
  if (userId) {
    const row = (await ctx.pool.query(`SELECT id FROM users WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL`, [userId, companyId])).rows[0];
    if (row) return row.id;
  }
  const owner = (await ctx.pool.query(`SELECT owner_user_id FROM companies WHERE id = $1`, [companyId])).rows[0];
  return owner?.owner_user_id;
}

async function executePushNotification(run, node, config) {
  const context = await buildRunContext(run);
  const title = resolveTemplate(config.title || "WolfCRM", context);
  const body = resolveTemplate(config.body || "", context);
  const requested = Array.isArray(config.user_ids) ? config.user_ids : [];
  const users = requested.length
    ? (await ctx.pool.query(`SELECT id FROM users WHERE company_id = $1 AND id = ANY($2::uuid[])`, [run.company_id, requested])).rows.map((r) => r.id)
    : (await ctx.pool.query(`SELECT id FROM users WHERE company_id = $1 AND deleted_at IS NULL`, [run.company_id])).rows.map((r) => r.id);
  const result = await ctx.sendPushToUsers(users, "automation", { title, body, payload: { type: "automation", run_id: run.id }, threadId: `automation_${run.id}` });
  return { sent: result.sent || 0, failed: result.failed || 0, skipped: !!result.skipped };
}

async function executeSmsSend(run, node, config) {
  return executeSmsSendShared(run, node, config, { mms: false });
}

async function executeMmsSend(run, node, config) {
  return executeSmsSendShared(run, node, config, { mms: true });
}

async function executeSmsSendShared(run, node, config, options = {}) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:sms_message_id`);
  if (existing) {
    const row = (await ctx.pool.query(
      `SELECT sm.id, sm.twilio_message_sid, sm.conversation_id, sm.to_number, sm.message_status, sm.media_count
         FROM sms_messages sm
         JOIN sms_conversations sc ON sc.id = sm.conversation_id
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sm.id::text = $1 AND pl.company_id = $2
        LIMIT 1`,
      [existing, run.company_id]
    )).rows[0];
    if (row) return { message_id: row.id, conversation_id: row.conversation_id, twilio_message_sid: row.twilio_message_sid, status: row.message_status, to_number: row.to_number, media_count: row.media_count, reused: true };
  }
  const context = await buildRunContext(run);
  const target = await resolveSmsTarget(run, context, config);
  const toNumber = normalizePhone(target.phone);
  if (!toNumber) throw new Error("contact_phone_required");
  const line = (await ctx.pool.query(`SELECT id, phone_number FROM phone_lines WHERE company_id = $1 AND active = true AND status = 'active' ORDER BY created_at ASC LIMIT 1`, [run.company_id])).rows[0];
  if (!line) throw new Error("phone_line_required");
  const body = resolveTemplate(config.body || "", context).slice(0, 1600);
  const media = Array.isArray(config.media) ? config.media.slice(0, 5) : [];
  if (!body && !media.length) throw new Error(options.mms ? "mms_body_or_media_required" : "sms_body_required");
  const policy = config.business_hours_policy || config.business_hours || "send_immediately";
  const eligibility = await canSendAutomatedCustomerMessage(run.company_id, toNumber, target.contact_id, policy);
  if (!eligibility.allowed) {
    await logRun(run, node, "warn", "sms.blocked", `Automated SMS blocked: ${eligibility.reason}`, { reason: eligibility.reason, resume_at: eligibility.resume_at || null });
    if (eligibility.reason === "deferred_until_business_hours" && eligibility.resume_at) {
      const wait = await ctx.pool.query(
        `INSERT INTO automation_waits(run_id, node_id, wait_type, resume_at, status)
         VALUES($1,$2,'until_datetime',$3,'waiting')
         RETURNING id, resume_at`,
        [run.id, node.id, eligibility.resume_at]
      );
      await ctx.pool.query(`UPDATE automation_runs SET status = 'waiting', updated_at = now() WHERE id = $1`, [run.id]);
      return { waiting: true, wait_id: wait.rows[0]?.id, reason: eligibility.reason, resume_at: eligibility.resume_at };
    }
    return { skipped: true, reason: eligibility.reason, to_number: toNumber };
  }
  const client = ctx.createTwilioClient();
  if (!client) throw new Error("twilio_not_configured");
  const sendPayload = { from: line.phone_number, to: toNumber, statusCallback: ctx.twilioPublicUrl("/webhooks/twilio/message-status") };
  if (body) sendPayload.body = body;
  if (media.length) sendPayload.mediaUrl = media.map((m) => resolveTemplate(m.url || m.media_url || m, context)).filter(Boolean);
  const sent = await client.messages.create(sendPayload);
  const conv = (await ctx.pool.query(
    `INSERT INTO sms_conversations(phone_line_id, external_phone_number, contact_id, last_message_at)
     VALUES($1,$2,$3,now())
     ON CONFLICT(phone_line_id, external_phone_number) DO UPDATE SET contact_id = COALESCE(sms_conversations.contact_id, EXCLUDED.contact_id), last_message_at = now(), updated_at = now()
     RETURNING id`,
    [line.id, toNumber, target.contact_id]
  )).rows[0];
  const msg = (await ctx.pool.query(
    `INSERT INTO sms_messages(conversation_id, twilio_message_sid, direction, from_number, to_number, body, message_status, media_count, media)
     VALUES($1,$2,'outbound',$3,$4,$5,$6,$7,$8::jsonb)
     RETURNING id, conversation_id, twilio_message_sid, to_number, message_status, media_count, created_at`,
    [conv.id, sent.sid || null, line.phone_number, toNumber, body || null, sent.status || "queued", media.length, JSON.stringify(media)]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:sms_message_id`, msg.id);
  await emitAutomationEvent({
    companyId: run.company_id,
    eventType: media.length ? "sms.mms_sent" : "sms.sent",
    subjectType: "sms_message",
    subjectId: msg.id,
    source: "automation",
    dedupeKey: `${media.length ? "sms.mms_sent" : "sms.sent"}:${msg.id}`,
    payload: automationPayload(run, node, { message_id: msg.id, conversation_id: conv.id, contact_id: target.contact_id, external_number: toNumber, status: msg.message_status, body, media_count: media.length })
  });
  await syncAutomationSchedulesForSmsOutbound(run.company_id, { ...msg, contact_id: target.contact_id, external_phone_number: toNumber });
  await syncAutomationSchedulesForSmsConversationActivity(run.company_id, conv.id, msg);
  return { message_id: msg.id, conversation_id: conv.id, twilio_message_sid: sent.sid, to_number: toNumber, status: msg.message_status, media_count: media.length };
}

function normalizePhone(value) {
  const s = (value || "").toString().trim();
  if (!s) return "";
  return s.startsWith("+") ? s : `+1${s.replace(/\D/g, "").slice(-10)}`;
}

async function resolveSmsTarget(run, context, config) {
  if (config.conversation_id || config.target_mode === "current_conversation") {
    const conversationId = resolveTemplate(config.conversation_id || context.sms?.conversation_id || "", context);
    const row = (await ctx.pool.query(
      `SELECT sc.id, sc.external_phone_number, sc.contact_id
         FROM sms_conversations sc
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sc.id::text = $1 AND pl.company_id = $2 AND sc.deleted_at IS NULL
        LIMIT 1`,
      [conversationId, run.company_id]
    )).rows[0];
    if (!row) throw new Error("sms_conversation_not_found");
    return { conversation_id: row.id, contact_id: row.contact_id, phone: row.external_phone_number };
  }
  if (config.target_mode === "phone_number" || config.target_mode === "phone_template" || config.phone || config.to_phone || config.to_number) {
    if (isBracedNumericLiteral(config.phone || config.to_phone || config.to_number)) throw new Error("sms_phone_number_wrapped_as_template");
    return { contact_id: null, phone: resolveTemplate(config.phone || config.to_phone || config.to_number, context) };
  }
  const contactId = await resolveContactId(run, context, config);
  const contact = (await ctx.pool.query(`SELECT id, phone FROM contacts WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL`, [contactId, run.company_id])).rows[0];
  if (!contact) throw new Error("contact_not_found");
  return { contact_id: contact.id, phone: contact.phone };
}

function isBracedNumericLiteral(value) {
  return /^\s*\{\{\s*\+?\d[\d\s().-]*\s*\}\}\s*$/.test(String(value || ""));
}

async function canSendAutomatedCustomerMessage(companyId, normalizedPhone, contactId, policy = "send_immediately") {
  const company = (await ctx.pool.query(
    `SELECT automated_customer_messages_enabled,
            automation_sms_max_per_contact_hour,
            automation_sms_max_per_contact_day,
            automation_sms_default_business_hours_policy
       FROM companies
      WHERE id = $1`,
    [companyId]
  )).rows[0] || {};
  if (company.automated_customer_messages_enabled === false) return { allowed: false, reason: "automated_customer_messages_disabled" };
  if (await isPhoneOptedOut(companyId, normalizedPhone)) return { allowed: false, reason: "recipient_opted_out" };
  const hourMax = Number(company.automation_sms_max_per_contact_hour || 6);
  const dayMax = Number(company.automation_sms_max_per_contact_day || 20);
  const rateKey = contactId ? "contact" : "phone";
  const rateValue = contactId || normalizedPhone;
  const rate = await ctx.pool.query(
    `SELECT COUNT(*) FILTER (WHERE sm.created_at >= now() - interval '1 hour')::int AS hour_count,
            COUNT(*) FILTER (WHERE sm.created_at >= now() - interval '1 day')::int AS day_count
       FROM sms_messages sm
       JOIN sms_conversations sc ON sc.id = sm.conversation_id
       JOIN phone_lines pl ON pl.id = sc.phone_line_id
      WHERE pl.company_id = $1
        AND sm.direction = 'outbound'
        AND ($2 = 'contact' AND sc.contact_id::text = $3 OR $2 = 'phone' AND sc.external_phone_number = $3)`,
    [companyId, rateKey, rateValue]
  );
  if (hourMax > 0 && Number(rate.rows[0]?.hour_count || 0) >= hourMax) return { allowed: false, reason: "automation_sms_hourly_limit" };
  if (dayMax > 0 && Number(rate.rows[0]?.day_count || 0) >= dayMax) return { allowed: false, reason: "automation_sms_daily_limit" };
  const effectivePolicy = policy || company.automation_sms_default_business_hours_policy || "send_immediately";
  if (effectivePolicy !== "send_immediately" && !(await companyWithinBusinessHours(companyId))) {
    if (effectivePolicy === "skip_if_outside_business_hours") return { allowed: false, reason: "outside_business_hours" };
    return { allowed: false, reason: "deferred_until_business_hours", resume_at: await nextCompanyBusinessOpening(companyId) };
  }
  return { allowed: true };
}

async function isPhoneOptedOut(companyId, normalizedPhone) {
  const phone = normalizePhone(normalizedPhone);
  if (!phone) return false;
  const row = (await ctx.pool.query(
    `SELECT status FROM phone_opt_outs WHERE company_id = $1 AND normalized_phone = $2 AND channel = 'sms' LIMIT 1`,
    [companyId, phone]
  )).rows[0];
  return row?.status === "opted_out";
}

export async function recordPhoneSmsConsent(companyId, phone, status, source = "twilio") {
  if (!ctx?.pool || !companyId || !phone) return;
  const normalized = normalizePhone(phone);
  if (!normalized) return;
  await ctx.pool.query(
    `INSERT INTO phone_opt_outs(company_id, normalized_phone, channel, status, source)
     VALUES($1,$2,'sms',$3,$4)
     ON CONFLICT(company_id, normalized_phone, channel)
     DO UPDATE SET status = EXCLUDED.status, source = EXCLUDED.source, updated_at = now()`,
    [companyId, normalized, status, source]
  );
}

async function companyWithinBusinessHours(companyId) {
  const row = (await ctx.pool.query(`SELECT business_days, business_open_time, business_close_time FROM companies WHERE id = $1`, [companyId])).rows[0];
  const now = new Date();
  const day = now.getUTCDay();
  const days = Array.isArray(row?.business_days) ? row.business_days.map(Number) : [1,2,3,4,5];
  if (!days.includes(day)) return false;
  const minute = now.getUTCHours() * 60 + now.getUTCMinutes();
  const open = timeToMinutes(row?.business_open_time || "09:00");
  const close = timeToMinutes(row?.business_close_time || "17:00");
  return minute >= open && minute < close;
}

async function nextCompanyBusinessOpening(companyId) {
  const row = (await ctx.pool.query(`SELECT business_days, business_open_time FROM companies WHERE id = $1`, [companyId])).rows[0];
  const days = Array.isArray(row?.business_days) ? row.business_days.map(Number) : [1,2,3,4,5];
  const open = timeToMinutes(row?.business_open_time || "09:00");
  const now = new Date();
  for (let i = 0; i < 14; i++) {
    const candidate = new Date(now.getTime() + i * 86400000);
    candidate.setUTCHours(Math.floor(open / 60), open % 60, 0, 0);
    if (days.includes(candidate.getUTCDay()) && candidate > now) return candidate.toISOString();
  }
  return new Date(now.getTime() + 3600000).toISOString();
}

function timeToMinutes(value) {
  const [h, m] = String(value || "09:00").split(":").map((n) => parseInt(n, 10) || 0);
  return Math.max(0, Math.min(1439, h * 60 + m));
}

async function executeInternalMessage(run, node, config) {
  const context = await buildRunContext(run);
  const body = resolveTemplate(config.body || "", context);
  if (!body.trim()) throw new Error("message_body_required");
  const sender = await resolveCompanyUser(run.company_id, config.sender_user_id);
  if (config.channel_id) {
    const channel = (await ctx.pool.query(`SELECT id FROM channels WHERE id = $1 AND company_id = $2 AND archived_at IS NULL`, [config.channel_id, run.company_id])).rows[0];
    if (!channel) throw new Error("channel_not_found");
    const id = randomUUID();
    await ctx.pool.query(`INSERT INTO messages(id, channel_id, sender_id, body) VALUES($1,$2,$3,$4)`, [id, channel.id, sender, body]);
    await emitInternalAutomationMessageEvent(run, node, { message_id: id, channel_id: channel.id, sender_user_id: sender, body });
    return { message_id: id, channel_id: channel.id };
  }
  let conversationId = config.conversation_id;
  if (!conversationId) {
    const recipients = Array.isArray(config.recipient_user_ids) ? config.recipient_user_ids : [];
    const valid = (await ctx.pool.query(`SELECT id FROM users WHERE company_id = $1 AND id = ANY($2::uuid[])`, [run.company_id, recipients])).rows.map((r) => r.id);
    if (!valid.length) throw new Error("recipient_required");
    conversationId = randomUUID();
    await ctx.pool.query(`INSERT INTO conversations(id, company_id, title, is_group, created_by) VALUES($1,$2,'Automation',true,$3)`, [conversationId, run.company_id, sender]);
    for (const userId of [...new Set([sender, ...valid])]) await ctx.pool.query(`INSERT INTO conversation_participants(id, conversation_id, user_id) VALUES($1,$2,$3)`, [randomUUID(), conversationId, userId]);
  }
  const member = await ctx.pool.query(`SELECT 1 FROM conversations WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL`, [conversationId, run.company_id]);
  if (!member.rowCount) throw new Error("conversation_not_found");
  const id = randomUUID();
  await ctx.pool.query(`INSERT INTO messages(id, conversation_id, sender_id, body) VALUES($1,$2,$3,$4)`, [id, conversationId, sender, body]);
  await emitInternalAutomationMessageEvent(run, node, { message_id: id, conversation_id: conversationId, sender_user_id: sender, body });
  return { message_id: id, conversation_id: conversationId };
}

async function executeInternalDm(run, node, config) {
  const requestedRecipient = config.recipient_user_id || config.user_id;
  if (!requestedRecipient) throw new Error("recipient_required");
  const recipient = await validateCompanyUser(run.company_id, requestedRecipient);
  const sender = await resolveCompanyUser(run.company_id, config.sender_user_id);
  let conversationId = (await ctx.pool.query(
    `SELECT c.id
       FROM conversations c
       JOIN conversation_participants a ON a.conversation_id = c.id AND a.user_id = $1
       JOIN conversation_participants b ON b.conversation_id = c.id AND b.user_id = $2
      WHERE c.company_id = $3
        AND c.deleted_at IS NULL
        AND c.is_group = false
      LIMIT 1`,
    [sender, recipient, run.company_id]
  )).rows[0]?.id;
  if (!conversationId) {
    conversationId = randomUUID();
    await ctx.pool.query(`INSERT INTO conversations(id, company_id, is_group, created_by) VALUES($1,$2,false,$3)`, [conversationId, run.company_id, sender]);
    for (const userId of [sender, recipient]) {
      await ctx.pool.query(`INSERT INTO conversation_participants(id, conversation_id, user_id) VALUES($1,$2,$3)`, [randomUUID(), conversationId, userId]);
    }
  }
  return executeInternalMessage(run, node, { ...config, conversation_id: conversationId, sender_user_id: sender });
}

async function executeInternalGroupMessage(run, node, config) {
  return executeInternalMessage(run, node, config);
}

async function executeInternalChannelMessage(run, node, config) {
  return executeInternalMessage(run, node, { ...config, channel_id: config.channel_id });
}

async function executeInternalCreateGroup(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:conversation_id`);
  if (existing) return { conversation_id: existing, reused: true };
  const title = String(config.title || "Automation Group").trim() || "Automation Group";
  const sender = await resolveCompanyUser(run.company_id, config.sender_user_id);
  const recipients = await resolveCompanyUsers(run.company_id, config.recipient_user_ids || config.user_ids || []);
  if (!recipients.length) throw new Error("participants_required");
  const id = randomUUID();
  await ctx.pool.query(`INSERT INTO conversations(id, company_id, title, is_group, created_by) VALUES($1,$2,$3,true,$4)`, [id, run.company_id, title, sender]);
  for (const userId of [...new Set([sender, ...recipients])]) {
    await ctx.pool.query(`INSERT INTO conversation_participants(id, conversation_id, user_id) VALUES($1,$2,$3)`, [randomUUID(), id, userId]);
  }
  await setRunVariable(run.id, `idempotency:${node.id}:conversation_id`, id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "internal.group_created", subjectType: "internal_conversation", subjectId: id, source: "automation", dedupeKey: `internal.group_created:${id}`, payload: automationPayload(run, node, { conversation_id: id, title }) });
  return { conversation_id: id };
}

async function executeInternalCreateChannel(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:channel_id`);
  if (existing) return { channel_id: existing, reused: true };
  const name = String(config.name || config.title || "").trim();
  if (!name) throw new Error("channel_name_required");
  const sender = await resolveCompanyUser(run.company_id, config.sender_user_id);
  const row = (await ctx.pool.query(
    `INSERT INTO channels(id, company_id, name, description, created_by)
     VALUES($1,$2,$3,$4,$5)
     RETURNING id`,
    [randomUUID(), run.company_id, name, config.description || null, sender]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:channel_id`, row.id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "internal.channel_created", subjectType: "channel", subjectId: row.id, source: "automation", dedupeKey: `internal.channel_created:${row.id}`, payload: automationPayload(run, node, { channel_id: row.id, name }) });
  return { channel_id: row.id };
}

async function executeInternalMarkConversationRead(run, _node, config) {
  const context = await buildRunContext(run);
  const conversationId = resolveTemplate(config.conversation_id || context.internal?.conversation_id || "", context);
  const userId = config.user_id || config.recipient_user_id
    ? await validateCompanyUser(run.company_id, config.user_id || config.recipient_user_id)
    : await resolveCompanyUser(run.company_id, null);
  if (!conversationId) throw new Error("conversation_required");
  const result = await ctx.pool.query(
    `UPDATE conversation_participants cp
        SET last_read_at = now()
       FROM conversations c
      WHERE cp.conversation_id = c.id
        AND c.company_id = $1
        AND cp.conversation_id::text = $2
        AND cp.user_id = $3`,
    [run.company_id, conversationId, userId]
  );
  if (!result.rowCount) throw new Error("conversation_not_found");
  return { conversation_id: conversationId, user_id: userId, read: true };
}

async function validateCompanyUser(companyId, userId) {
  const row = (await ctx.pool.query(`SELECT id FROM users WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL`, [userId, companyId])).rows[0];
  if (!row) throw new Error("user_not_found");
  return row.id;
}

async function emitInternalAutomationMessageEvent(run, node, message) {
  await emitAutomationEvent({
    companyId: run.company_id,
    eventType: message.channel_id ? "internal.channel_message_received" : "internal.message_received",
    subjectType: "internal_message",
    subjectId: message.message_id,
    source: "automation",
    dedupeKey: `internal.message:${message.message_id}`,
    payload: automationPayload(run, node, {
      message_id: message.message_id,
      conversation_id: message.conversation_id || null,
      channel_id: message.channel_id || null,
      sender_user_id: message.sender_user_id,
      body: message.body,
      message_body: message.body
    })
  });
}

async function executeSmsConversationRead(run, _node, config) {
  const context = await buildRunContext(run);
  const conversationId = resolveTemplate(config.conversation_id || context.sms?.conversation_id || "", context);
  if (!conversationId) throw new Error("sms_conversation_required");
  const row = (await ctx.pool.query(
    `UPDATE sms_conversations sc
        SET last_read_at = now(), updated_at = now()
       FROM phone_lines pl
      WHERE sc.id::text = $1 AND pl.id = sc.phone_line_id AND pl.company_id = $2
      RETURNING sc.id`,
    [conversationId, run.company_id]
  )).rows[0];
  if (!row) throw new Error("sms_conversation_not_found");
  return { conversation_id: row.id, read: true };
}

async function executeSmsConversationUnread(run, _node, config) {
  const context = await buildRunContext(run);
  const conversationId = resolveTemplate(config.conversation_id || context.sms?.conversation_id || "", context);
  const row = (await ctx.pool.query(
    `UPDATE sms_conversations sc
        SET last_read_at = NULL, updated_at = now()
       FROM phone_lines pl
      WHERE sc.id::text = $1 AND pl.id = sc.phone_line_id AND pl.company_id = $2
      RETURNING sc.id`,
    [conversationId, run.company_id]
  )).rows[0];
  if (!row) throw new Error("sms_conversation_not_found");
  return { conversation_id: row.id, unread: true };
}

async function executeSmsDeleteLocalMessage(run, _node, config) {
  const context = await buildRunContext(run);
  const messageId = resolveTemplate(config.message_id || context.sms?.message_id || "", context);
  const row = (await ctx.pool.query(
    `UPDATE sms_messages sm
        SET deleted_at = now(), updated_at = now()
       FROM sms_conversations sc
       JOIN phone_lines pl ON pl.id = sc.phone_line_id
      WHERE sm.id::text = $1 AND sm.conversation_id = sc.id AND pl.company_id = $2
      RETURNING sm.id, sm.conversation_id`,
    [messageId, run.company_id]
  )).rows[0];
  if (!row) throw new Error("sms_message_not_found");
  return { message_id: row.id, conversation_id: row.conversation_id, deleted_local: true };
}

async function executeSmsDeleteLocalConversation(run, _node, config) {
  const context = await buildRunContext(run);
  const conversationId = resolveTemplate(config.conversation_id || context.sms?.conversation_id || "", context);
  const row = (await ctx.pool.query(
    `UPDATE sms_conversations sc
        SET deleted_at = now(), updated_at = now()
       FROM phone_lines pl
      WHERE sc.id::text = $1 AND pl.id = sc.phone_line_id AND pl.company_id = $2
      RETURNING sc.id`,
    [conversationId, run.company_id]
  )).rows[0];
  if (!row) throw new Error("sms_conversation_not_found");
  await ctx.pool.query(`UPDATE sms_messages SET deleted_at = COALESCE(deleted_at, now()), updated_at = now() WHERE conversation_id = $1`, [row.id]);
  return { conversation_id: row.id, deleted_local: true };
}

async function executeCreateContactFromNumber(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:contact_id`);
  if (existing) return { contact_id: existing, reused: true };
  const context = await buildRunContext(run);
  const phone = normalizePhone(resolveTemplate(config.phone || context.sms?.external_number || context.call?.external_number || context.voicemail?.external_number || "", context));
  if (!phone) throw new Error("phone_required");
  const existingContact = (await ctx.pool.query(
    `SELECT id FROM contacts
      WHERE company_id = $1
        AND regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g') = regexp_replace($2, '[^0-9]', '', 'g')
        AND deleted_at IS NULL
      LIMIT 1`,
    [run.company_id, phone]
  )).rows[0];
  if (existingContact) return { contact_id: existingContact.id, reused: true };
  const created = (await ctx.pool.query(
    `INSERT INTO contacts(id, company_id, name, phone, source, tags)
     VALUES($1,$2,$3,$4,$5,$6)
     RETURNING id`,
    [randomUUID(), run.company_id, resolveTemplate(config.name || "New Contact", context), phone, config.source || "automation", normalizeTags(config.tags || []).join(", ")]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:contact_id`, created.id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "contact.created", subjectType: "contact", subjectId: created.id, source: "automation", dedupeKey: `contact.created:${created.id}`, payload: automationPayload(run, node, { contact_id: created.id, phone }) });
  return { contact_id: created.id, phone };
}

async function executeCallSetDisposition(run, _node, config) {
  const context = await buildRunContext(run);
  const callId = resolveTemplate(config.call_id || context.call?.id || "", context);
  const disposition = String(config.disposition || "").trim();
  if (!callId || !disposition) throw new Error("call_disposition_required");
  const row = (await ctx.pool.query(`UPDATE phone_calls SET disposition = $3, updated_at = now() WHERE id::text = $1 AND company_id = $2 RETURNING id, disposition`, [callId, run.company_id, disposition])).rows[0];
  if (!row) throw new Error("call_not_found");
  return { call_id: row.id, disposition: row.disposition };
}

async function executeCallCreateCallbackTask(run, node, config) {
  const context = await buildRunContext(run);
  const title = config.title || `Call ${context.contact?.name || context.call?.external_number || "customer"} back`;
  return executeTaskCreate(run, node, { ...config, title, contact_id: config.contact_id || context.call?.contact_id || context.contact?.id });
}

async function executeCallFollowupSms(run, node, config) {
  const context = await buildRunContext(run);
  return executeSmsSendShared(run, node, { ...config, phone: config.phone || context.call?.external_number, contact_id: config.contact_id || context.call?.contact_id }, { mms: false });
}

async function executeCallAddContactNote(run, node, config) {
  const context = await buildRunContext(run);
  return executeContactAddNote(run, node, { ...config, contact_id: config.contact_id || context.call?.contact_id || context.contact?.id, note: config.note || config.body || "Call follow-up note" });
}

async function executeVoicemailMarkRead(run, _node, config) {
  return updateVoicemailReadState(run, config, true);
}

async function executeVoicemailMarkUnread(run, _node, config) {
  return updateVoicemailReadState(run, config, false);
}

async function updateVoicemailReadState(run, config, read) {
  const context = await buildRunContext(run);
  const voicemailId = resolveTemplate(config.voicemail_id || context.voicemail?.id || "", context);
  if (!voicemailId) throw new Error("voicemail_required");
  const row = (await ctx.pool.query(`UPDATE voicemails SET is_read = $3, updated_at = now() WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL RETURNING id, is_read`, [voicemailId, run.company_id, read])).rows[0];
  if (!row) throw new Error("voicemail_not_found");
  return { voicemail_id: row.id, read: row.is_read };
}

async function executeVoicemailDelete(run, _node, config) {
  const context = await buildRunContext(run);
  const voicemailId = resolveTemplate(config.voicemail_id || context.voicemail?.id || "", context);
  const row = (await ctx.pool.query(`UPDATE voicemails SET deleted_at = now(), updated_at = now() WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL RETURNING id`, [voicemailId, run.company_id])).rows[0];
  if (!row) throw new Error("voicemail_not_found");
  return { voicemail_id: row.id, deleted: true };
}

async function executeVoicemailCreateCallbackTask(run, node, config) {
  const context = await buildRunContext(run);
  const title = config.title || `Return voicemail from ${context.contact?.name || context.voicemail?.external_number || "customer"}`;
  return executeTaskCreate(run, node, { ...config, title, contact_id: config.contact_id || context.voicemail?.contact_id || context.contact?.id });
}

async function executeVoicemailFollowupSms(run, node, config) {
  const context = await buildRunContext(run);
  return executeSmsSendShared(run, node, { ...config, phone: config.phone || context.voicemail?.external_number, contact_id: config.contact_id || context.voicemail?.contact_id }, { mms: false });
}

async function executeQuoteCreate(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:quote_id`);
  if (existing) return { quote_id: existing, reused: true };
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const items = normalizeQuoteLineItems(resolveConfig(config.line_items || config.items || [], context));
  if (!items.length) throw new Error("quote_line_items_required");
  const total = computeQuoteTotalCents(items);
  const owner = await resolveCompanyUser(run.company_id, config.user_id);
  const expiresAt = resolveDateExpression(config.expires_at || "", context);
  const row = (await ctx.pool.query(
    `INSERT INTO quotes(user_id, company_id, contact_id, title, line_items, total_cents, notes, status, expires_at)
     VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,'draft',$8)
     RETURNING *`,
    [owner, run.company_id, contactId, resolveTemplate(config.title || "Automation Quote", context), JSON.stringify(items), total, resolveTemplate(config.notes || "", context) || null, expiresAt ? expiresAt.toISOString() : null]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:quote_id`, row.id);
  await emitFinancialEvent(run, node, "quote.created", "quote", row.id, quotePayload(row));
  await syncAutomationSchedulesForQuote(run.company_id, row);
  return { quote_id: row.id, contact_id: row.contact_id, subtotal_cents: total, total_cents: total, status: row.status };
}

async function executeQuoteUpdate(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const items = config.line_items || config.items ? normalizeQuoteLineItems(resolveConfig(config.line_items || config.items || [], context)) : null;
  const total = items ? computeQuoteTotalCents(items) : null;
  const expiresAt = config.expires_at ? resolveDateExpression(config.expires_at, context) : null;
  const row = (await ctx.pool.query(
    `UPDATE quotes
        SET title = COALESCE($3, title),
            line_items = COALESCE($4::jsonb, line_items),
            total_cents = COALESCE($5, total_cents),
            notes = COALESCE($6, notes),
            expires_at = COALESCE($7::timestamptz, expires_at),
            updated_at = now()
      WHERE id::text = $1 AND company_id = $2
      RETURNING *`,
    [quote.id, run.company_id, config.title ? resolveTemplate(config.title, context) : null, items ? JSON.stringify(items) : null, total, config.notes ? resolveTemplate(config.notes, context) : null, expiresAt ? expiresAt.toISOString() : null]
  )).rows[0];
  await emitQuoteChangeEvents(run, node, quote, row);
  await syncAutomationSchedulesForQuote(run.company_id, row);
  return { quote_id: row.id, total_cents: row.total_cents, status: row.status };
}

async function executeQuoteDelete(run, node, config) {
  if (config.confirm_delete !== true) throw new Error("delete_confirmation_required");
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  await ctx.pool.query(`DELETE FROM quotes WHERE id = $1 AND company_id = $2`, [quote.id, run.company_id]);
  await cancelScheduledForSubject(run.company_id, "quote", quote.id, ["quote.expired", "quote.followup_due"]);
  await emitFinancialEvent(run, node, "quote.deleted", "quote", quote.id, quotePayload(quote));
  return { quote_id: quote.id, deleted: true };
}

async function executeQuoteAddLineItem(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const item = normalizeQuoteLineItems([resolveConfig({ description: config.description || config.service || "Service", qty: config.qty || 1, price_cents: config.price_cents || 0 }, context)])[0];
  if (!item) throw new Error("quote_line_item_required");
  const items = [...(Array.isArray(quote.line_items) ? quote.line_items : []), item];
  return updateQuoteItems(run, node, quote, items);
}

async function executeQuoteRemoveLineItem(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const needle = resolveTemplate(config.description || config.service || "", context).toLowerCase();
  const items = (Array.isArray(quote.line_items) ? quote.line_items : []).filter((item) => !needle || !String(item.description || item.name || "").toLowerCase().includes(needle));
  return updateQuoteItems(run, node, quote, items);
}

async function executeQuoteReplaceLineItems(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const items = normalizeQuoteLineItems(resolveConfig(config.line_items || config.items || [], context));
  return updateQuoteItems(run, node, quote, items);
}

async function updateQuoteItems(run, node, quote, items) {
  const total = computeQuoteTotalCents(items);
  const row = (await ctx.pool.query(`UPDATE quotes SET line_items = $3::jsonb, total_cents = $4, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [quote.id, run.company_id, JSON.stringify(items), total])).rows[0];
  await emitQuoteChangeEvents(run, node, quote, row);
  await syncAutomationSchedulesForQuote(run.company_id, row);
  return { quote_id: row.id, total_cents: row.total_cents, line_item_count: items.length };
}

async function executeQuoteSetStatus(run, node, config) {
  return setQuoteStatus(run, node, config.status || "draft", config);
}
async function executeQuoteMarkSent(run, node, config) { return setQuoteStatus(run, node, "sent", config); }
async function executeQuoteMarkAccepted(run, node, config) { return setQuoteStatus(run, node, "accepted", config); }
async function executeQuoteMarkDeclined(run, node, config) { return setQuoteStatus(run, node, "declined", config); }

async function setQuoteStatus(run, node, status, config) {
  if (!["draft", "sent", "accepted", "declined", "expired", "converted"].includes(status)) throw new Error("invalid_quote_status");
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const row = (await ctx.pool.query(
    `UPDATE quotes
        SET status = $3,
            sent_at = CASE WHEN $3 = 'sent' THEN COALESCE(sent_at, now()) ELSE sent_at END,
            accepted_at = CASE WHEN $3 = 'accepted' THEN COALESCE(accepted_at, now()) ELSE accepted_at END,
            declined_at = CASE WHEN $3 = 'declined' THEN COALESCE(declined_at, now()) ELSE declined_at END,
            updated_at = now()
      WHERE id = $1 AND company_id = $2
      RETURNING *`,
    [quote.id, run.company_id, status]
  )).rows[0];
  await emitQuoteChangeEvents(run, node, quote, row);
  await syncAutomationSchedulesForQuote(run.company_id, row);
  return { quote_id: row.id, status: row.status };
}

async function executeQuoteSetExpiration(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const expiresAt = resolveDateExpression(config.expires_at || config.until || "", context);
  if (!expiresAt) throw new Error("quote_expiration_required");
  const row = (await ctx.pool.query(`UPDATE quotes SET expires_at = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [quote.id, run.company_id, expiresAt.toISOString()])).rows[0];
  await emitQuoteChangeEvents(run, node, quote, row);
  await syncAutomationSchedulesForQuote(run.company_id, row);
  return { quote_id: row.id, expires_at: row.expires_at };
}

async function executeQuoteConvertToJob(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  const job = await executeJobCreate(run, node, {
    ...config,
    contact_id: quote.contact_id,
    title: config.title || quote.title || "Quoted job",
    service_items: quote.line_items || [],
    price_cents: config.copy_total_to_price === false ? config.price_cents : quote.total_cents
  });
  await ctx.pool.query(`UPDATE quotes SET status = 'converted', converted_job_id = $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [quote.id, run.company_id, job.job_id]);
  await cancelScheduledForSubject(run.company_id, "quote", quote.id, ["quote.expired", "quote.followup_due"]);
  await emitFinancialEvent(run, node, "quote.converted_to_job", "quote", quote.id, { ...quotePayload(quote), job_id: job.job_id });
  await emitFinancialEvent(run, node, "quote.scheduled", "quote", quote.id, { ...quotePayload(quote), job_id: job.job_id });
  return { quote_id: quote.id, job_id: job.job_id };
}

async function executeQuoteFollowupTask(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  return executeTaskCreate(run, node, { ...config, title: config.title || `Follow up on quote ${quote.title || quote.id}`, contact_id: quote.contact_id });
}

async function executeQuoteCreateInvoice(run, node, config) {
  const context = await buildRunContext(run);
  const quote = await resolveQuote(run, context, config);
  return executeInvoiceCreate(run, node, { ...config, quote_id: quote.id, contact_id: quote.contact_id, line_items: quote.line_items, total_cents: quote.total_cents });
}

async function executeInvoiceCreate(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:invoice_id`);
  if (existing) return { invoice_id: existing, reused: true };
  const context = await buildRunContext(run);
  const owner = await resolveCompanyUser(run.company_id, config.user_id);
  const contactId = config.contact_id ? resolveTemplate(config.contact_id, context) : (context.quote?.contact_id || context.job?.contact_id || context.contact?.id);
  if (contactId) await validateSubject(run.company_id, "contact", contactId);
  const items = normalizeQuoteLineItems(resolveConfig(config.line_items || [], context));
  const total = intOrNull(config.total_cents) ?? computeQuoteTotalCents(items);
  const due = resolveDateExpression(config.due_at || "", context);
  const row = (await ctx.pool.query(
    `INSERT INTO invoices(company_id, user_id, created_by_user_id, contact_id, quote_id, job_id, status, line_items, subtotal_cents, total_cents, currency, due_at, metadata)
     VALUES($1,$2,$2,$3,$4,$5,'draft',$6::jsonb,$7,$7,$8,$9,$10::jsonb)
     RETURNING *`,
    [run.company_id, owner, contactId || null, config.quote_id || null, config.job_id || null, JSON.stringify(items), total, (config.currency || "usd").toLowerCase(), due ? due.toISOString() : null, JSON.stringify({ source: "automation" })]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:invoice_id`, row.id);
  await emitFinancialEvent(run, node, "invoice.created", "invoice", row.id, invoicePayload(row));
  await syncAutomationSchedulesForInvoice(run.company_id, row);
  return { invoice_id: row.id, contact_id: row.contact_id, total_cents: row.total_cents, status: row.status, due_at: row.due_at };
}

async function executeInvoiceIssue(run, node, config) {
  const invoice = await resolveInvoice(run, await buildRunContext(run), config);
  const row = (await ctx.pool.query(`UPDATE invoices SET status = 'issued', issued_at = COALESCE(issued_at, now()), due_at = COALESCE($3::timestamptz, due_at), updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [invoice.id, run.company_id, config.due_at || null])).rows[0];
  await emitFinancialEvent(run, node, "invoice.issued", "invoice", row.id, invoicePayload(row));
  await syncAutomationSchedulesForInvoice(run.company_id, row);
  return { invoice_id: row.id, status: row.status, due_at: row.due_at };
}

async function executeInvoiceSetDueDate(run, node, config) {
  const context = await buildRunContext(run);
  const invoice = await resolveInvoice(run, context, config);
  const due = resolveDateExpression(config.due_at || "", context);
  if (!due) throw new Error("invoice_due_required");
  const row = (await ctx.pool.query(`UPDATE invoices SET due_at = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [invoice.id, run.company_id, due.toISOString()])).rows[0];
  await emitFinancialEvent(run, node, "invoice.updated", "invoice", row.id, invoicePayload(row));
  await syncAutomationSchedulesForInvoice(run.company_id, row);
  return { invoice_id: row.id, due_at: row.due_at };
}

async function executeInvoiceVoid(run, node, config) {
  if (config.confirm_void !== true) throw new Error("invoice_void_confirmation_required");
  const invoice = await resolveInvoice(run, await buildRunContext(run), config);
  const row = (await ctx.pool.query(`UPDATE invoices SET status = 'void', updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [invoice.id, run.company_id])).rows[0];
  await cancelScheduledForSubject(run.company_id, "invoice", row.id, ["invoice.due", "invoice.overdue"]);
  await emitFinancialEvent(run, node, "invoice.voided", "invoice", row.id, invoicePayload(row));
  return { invoice_id: row.id, status: row.status };
}

async function executeInvoiceCreatePaymentRequest(run, node, config) {
  const context = await buildRunContext(run);
  const invoice = await resolveInvoice(run, context, config);
  return executePaymentCreateRequest(run, node, { ...config, contact_id: invoice.contact_id, amount_cents: invoice.total_cents, description: config.description || `Invoice ${invoice.id}`, invoice_id: invoice.id });
}

async function executeInvoiceSendPaymentLink(run, node, config) {
  const payment = await executeInvoiceCreatePaymentRequest(run, node, config);
  const context = await buildRunContext(run);
  return executeSmsSendShared(run, node, { ...config, contact_id: context.invoice?.contact_id || config.contact_id, body: config.body || `Your payment request is ready: ${payment.payment_url || payment.payment_record_id}` }, { mms: false });
}

async function executeInvoiceFollowupTask(run, node, config) {
  const invoice = await resolveInvoice(run, await buildRunContext(run), config);
  return executeTaskCreate(run, node, { ...config, title: config.title || "Invoice follow-up", contact_id: invoice.contact_id });
}

async function executePaymentCreateRequest(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:payment_record_id`);
  if (existing) return { payment_record_id: existing, reused: true };
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const amount = intOrNull(resolveTemplate(config.amount_cents || config.amount || "", context));
  if (!amount || amount < 50) throw new Error("payment_amount_required");
  const owner = await resolveCompanyUser(run.company_id, config.user_id);
  const settings = (await ctx.pool.query(`SELECT stripe_account_id, stripe_default_currency FROM business_settings WHERE user_id = $1`, [owner])).rows[0];
  if (!settings?.stripe_account_id) throw new Error("stripe_not_connected");
  const stripe = ctx.getStripe ? ctx.getStripe() : null;
  if (!stripe) throw new Error("stripe_not_configured");
  const contact = (await ctx.pool.query(`SELECT name, email, phone, address FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, run.company_id])).rows[0];
  const currency = (config.currency || settings.stripe_default_currency || "usd").toLowerCase();
  const customer = await stripe.customers.create({ name: contact?.name || undefined, email: contact?.email || undefined, phone: contact?.phone || undefined, metadata: { wolfcrm_contact_id: contactId } }, { stripeAccount: settings.stripe_account_id, idempotencyKey: `auto_${run.id}_${node.id}_customer` });
  const intent = await stripe.paymentIntents.create({
    amount,
    currency,
    customer: customer.id,
    description: resolveTemplate(config.description || "WolfCRM payment request", context),
    automatic_payment_methods: { enabled: true },
    metadata: { wolfcrm_contact_id: contactId, wolfcrm_run_id: run.id, wolfcrm_node_id: node.id, wolfcrm_invoice_id: config.invoice_id || "" }
  }, { stripeAccount: settings.stripe_account_id, idempotencyKey: `auto_${run.id}_${node.id}_payment_intent` });
  const row = (await ctx.pool.query(
    `INSERT INTO payment_records(user_id, company_id, created_by_user_id, contact_id, payment_type, status, amount_cents, currency, description, stripe_connected_account_id, stripe_customer_id, stripe_payment_intent_id, stripe_invoice_id)
     VALUES($1,$2,$1,$3,'automation_request','pending',$4,$5,$6,$7,$8,$9,$10)
     RETURNING *`,
    [owner, run.company_id, contactId, amount, currency, resolveTemplate(config.description || "Automation payment request", context), settings.stripe_account_id, customer.id, intent.id, config.invoice_id || null]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:payment_record_id`, row.id);
  await emitFinancialEvent(run, node, "payment.created", "payment", row.id, paymentPayload(row));
  await emitFinancialEvent(run, node, "payment.started", "payment", row.id, paymentPayload(row));
  return { payment_record_id: row.id, payment_intent_id: intent.id, amount_cents: amount, currency, payment_url: null };
}

async function executePaymentFollowupTask(run, node, config) {
  const payment = await resolvePayment(run, await buildRunContext(run), config);
  return executeTaskCreate(run, node, { ...config, title: config.title || "Payment follow-up", contact_id: payment.contact_id });
}

async function executePaymentSendSms(run, node, config) {
  const payment = await resolvePayment(run, await buildRunContext(run), config);
  return executeSmsSendShared(run, node, { ...config, contact_id: payment.contact_id, body: config.body || "Your payment needs attention." }, { mms: false });
}

async function executePaymentSendPush(run, node, config) {
  return executePushNotification(run, node, { ...config, title: config.title || "Payment update", body: config.body || "{{event.type}}" });
}

async function executePaymentRecordManual(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:payment_record_id`);
  if (existing) return { payment_record_id: existing, reused: true };
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const amount = intOrNull(resolveTemplate(config.amount_cents || "", context));
  if (!amount || amount < 1) throw new Error("payment_amount_required");
  const owner = await resolveCompanyUser(run.company_id, config.user_id);
  const row = (await ctx.pool.query(`INSERT INTO payment_records(user_id, company_id, created_by_user_id, contact_id, payment_type, status, amount_cents, currency, description) VALUES($1,$2,$1,$3,'manual','succeeded',$4,$5,$6) RETURNING *`, [owner, run.company_id, contactId, amount, (config.currency || "usd").toLowerCase(), resolveTemplate(config.description || "Manual payment", context)])).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:payment_record_id`, row.id);
  await emitFinancialEvent(run, node, "payment.succeeded", "payment", row.id, paymentPayload(row));
  return { payment_record_id: row.id, amount_cents: amount, status: row.status };
}

async function executeServicePlanCreate(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:service_plan_id`);
  if (existing) return { service_plan_id: existing, reused: true };
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const owner = await resolveCompanyUser(run.company_id, config.user_id);
  const firstDate = resolveDateExpression(config.first_service_date || config.next_service_date || "", context);
  const price = intOrNull(resolveTemplate(config.price_cents || "", context));
  if (!price || price < 1) throw new Error("service_plan_price_required");
  const row = (await ctx.pool.query(
    `INSERT INTO service_plans(user_id, company_id, created_by_user_id, contact_id, plan_name, status, price_cents, currency, billing_interval, billing_interval_count, service_interval, service_interval_count, first_service_date, next_service_date, included_services, notes)
     VALUES($1,$2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::date,$12::date,$13,$14)
     RETURNING *`,
    [owner, run.company_id, contactId, resolveTemplate(config.plan_name || "Automation Service Plan", context), config.status || "draft", price, (config.currency || "usd").toLowerCase(), config.billing_interval || "month", Math.max(1, Number(config.billing_interval_count || 1)), config.service_interval || "month", Math.max(1, Number(config.service_interval_count || 1)), firstDate ? firstDate.toISOString().slice(0, 10) : null, resolveTemplate(config.included_services || "", context) || null, resolveTemplate(config.notes || "", context) || null]
  )).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:service_plan_id`, row.id);
  await emitFinancialEvent(run, node, "service_plan.created", "service_plan", row.id, servicePlanPayload(row));
  await syncAutomationSchedulesForServicePlan(run.company_id, row);
  return { service_plan_id: row.id, contact_id: row.contact_id, status: row.status, next_service_date: row.next_service_date };
}

async function executeServicePlanUpdate(run, node, config) {
  const context = await buildRunContext(run);
  const plan = await resolveServicePlan(run, context, config);
  const row = (await ctx.pool.query(
    `UPDATE service_plans
        SET plan_name = COALESCE($3, plan_name),
            price_cents = COALESCE($4, price_cents),
            billing_interval = COALESCE($5, billing_interval),
            billing_interval_count = COALESCE($6, billing_interval_count),
            service_interval = COALESCE($7, service_interval),
            service_interval_count = COALESCE($8, service_interval_count),
            first_service_date = COALESCE($9::date, first_service_date),
            next_service_date = COALESCE($10::date, next_service_date),
            included_services = COALESCE($11, included_services),
            notes = COALESCE($12, notes),
            updated_at = now()
      WHERE id = $1 AND company_id = $2
      RETURNING *`,
    [plan.id, run.company_id, config.plan_name || null, intOrNull(config.price_cents), config.billing_interval || null, intOrNull(config.billing_interval_count), config.service_interval || null, intOrNull(config.service_interval_count), config.first_service_date || null, config.next_service_date || null, config.included_services || null, config.notes || null]
  )).rows[0];
  await emitServicePlanChangeEvents(run, node, plan, row);
  await syncAutomationSchedulesForServicePlan(run.company_id, row);
  return { service_plan_id: row.id, status: row.status, next_service_date: row.next_service_date };
}

async function executeServicePlanActivate(run, node, config) { return setServicePlanStatus(run, node, config, "active"); }
async function executeServicePlanPause(run, node, config) { return setServicePlanStatus(run, node, config, "paused"); }
async function executeServicePlanResume(run, node, config) { return setServicePlanStatus(run, node, config, "active", "service_plan.resumed"); }

async function setServicePlanStatus(run, node, config, status, eventOverride = null) {
  const plan = await resolveServicePlan(run, await buildRunContext(run), config);
  const row = (await ctx.pool.query(`UPDATE service_plans SET status = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [plan.id, run.company_id, status])).rows[0];
  const eventType = eventOverride || (status === "active" ? "service_plan.activated" : status === "paused" ? "service_plan.paused" : "service_plan.updated");
  await emitFinancialEvent(run, node, eventType, "service_plan", row.id, servicePlanPayload(row));
  await syncAutomationSchedulesForServicePlan(run.company_id, row);
  return { service_plan_id: row.id, status: row.status };
}

async function executeServicePlanCancel(run, node, config) {
  if (config.confirm_cancel !== true) throw new Error("service_plan_cancel_confirmation_required");
  const plan = await resolveServicePlan(run, await buildRunContext(run), config);
  const stripe = ctx.getStripe ? ctx.getStripe() : null;
  if (stripe && plan.stripe_subscription_id && plan.stripe_connected_account_id) {
    await stripe.subscriptions.cancel(plan.stripe_subscription_id, {}, { stripeAccount: plan.stripe_connected_account_id, idempotencyKey: `auto_${run.id}_${node.id}_cancel_subscription` }).catch((e) => { throw new Error(`stripe_cancel_failed:${e?.message || "unknown"}`); });
  }
  const row = (await ctx.pool.query(`UPDATE service_plans SET status = 'canceled', updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [plan.id, run.company_id])).rows[0];
  await cancelScheduledForSubject(run.company_id, "service_plan", row.id, ["service_plan.service_upcoming", "service_plan.service_due", "service_plan.service_overdue"]);
  await emitFinancialEvent(run, node, "service_plan.canceled", "service_plan", row.id, servicePlanPayload(row));
  return { service_plan_id: row.id, status: row.status };
}

async function executeServicePlanMarkServiced(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:service_event_id`);
  if (existing) return { service_event_id: existing, reused: true };
  const context = await buildRunContext(run);
  const plan = await resolveServicePlan(run, context, config);
  const completedDate = (resolveDateExpression(config.completed_date || "", context) || new Date()).toISOString().slice(0, 10);
  const next = addDaysISO(completedDate, serviceIntervalDays(plan.service_interval, plan.service_interval_count));
  const row = (await ctx.pool.query(`UPDATE service_plans SET last_service_date = $3::date, next_service_date = $4::date, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [plan.id, run.company_id, completedDate, next])).rows[0];
  const owner = await resolveCompanyUser(run.company_id, plan.user_id);
  const event = (await ctx.pool.query(`INSERT INTO service_plan_events(user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, completed_date, notes) VALUES($1,$2,$1,$3,$4,'serviced',$5,$6) RETURNING id`, [owner, run.company_id, row.id, row.contact_id, completedDate, "Marked serviced by automation"])).rows[0];
  await setRunVariable(run.id, `idempotency:${node.id}:service_event_id`, event.id);
  await emitFinancialEvent(run, node, "service_plan.serviced", "service_plan", row.id, { ...servicePlanPayload(row), completed_date: completedDate });
  await syncAutomationSchedulesForServicePlan(run.company_id, row);
  return { service_plan_id: row.id, service_event_id: event.id, completed_date: completedDate, next_service_date: next };
}

async function executeServicePlanSetPrice(run, node, config) { return executeServicePlanUpdate(run, node, { ...config, price_cents: config.price_cents }); }
async function executeServicePlanSetServiceInterval(run, node, config) { return executeServicePlanUpdate(run, node, { ...config, service_interval: config.service_interval, service_interval_count: config.service_interval_count }); }
async function executeServicePlanSetBillingInterval(run, node, config) { return executeServicePlanUpdate(run, node, { ...config, billing_interval: config.billing_interval, billing_interval_count: config.billing_interval_count }); }
async function executeServicePlanSetNextServiceDate(run, node, config) { return executeServicePlanUpdate(run, node, { ...config, next_service_date: config.next_service_date }); }

async function executeServicePlanCreateNextJob(run, node, config) {
  const plan = await resolveServicePlan(run, await buildRunContext(run), config);
  return executeJobCreate(run, node, { ...config, contact_id: plan.contact_id, title: config.title || plan.plan_name || "Service plan job", start_at: config.start_at || plan.next_service_date, price_cents: config.price_cents || plan.price_cents });
}

async function executeServicePlanCreateTask(run, node, config) {
  const plan = await resolveServicePlan(run, await buildRunContext(run), config);
  return executeTaskCreate(run, node, { ...config, title: config.title || `Schedule next service for {{contact.name}}`, contact_id: plan.contact_id, due_date: config.due_date || plan.next_service_date });
}

async function executeServicePlanSendSchedulingSms(run, node, config) {
  const plan = await resolveServicePlan(run, await buildRunContext(run), config);
  return executeSmsSendShared(run, node, { ...config, contact_id: plan.contact_id, body: config.body || "It is time to schedule your next service." }, { mms: false });
}

async function executeServicePlanPaymentFollowup(run, node, config) {
  const plan = await resolveServicePlan(run, await buildRunContext(run), config);
  return executeTaskCreate(run, node, { ...config, title: config.title || "Service plan payment follow-up", contact_id: plan.contact_id });
}

function normalizeQuoteLineItems(items) {
  const array = Array.isArray(items) ? items : [];
  return array.map((item) => ({
    description: String(item.description || item.name || item.service || "Service").trim(),
    qty: Math.max(0, Number(item.qty ?? item.quantity ?? 1) || 0),
    price_cents: Math.max(0, Math.round(Number(item.price_cents ?? item.unit_price_cents ?? item.price ?? 0) || 0))
  })).filter((item) => item.description && item.qty > 0);
}

function computeQuoteTotalCents(items) {
  return normalizeQuoteLineItems(items).reduce((sum, item) => sum + Math.round(item.qty * item.price_cents), 0);
}

async function resolveQuote(run, context, config) {
  const id = resolveTemplate(config.quote_id || context.quote?.id || (run.subject_type === "quote" ? run.subject_id : ""), context);
  if (!id) throw new Error("quote_required");
  const row = (await ctx.pool.query(`SELECT * FROM quotes WHERE id::text = $1 AND company_id = $2`, [id, run.company_id])).rows[0];
  if (!row) throw new Error("quote_not_found");
  return row;
}

async function resolveInvoice(run, context, config) {
  const id = resolveTemplate(config.invoice_id || context.invoice?.id || (run.subject_type === "invoice" ? run.subject_id : ""), context);
  if (!id) throw new Error("invoice_required");
  const row = (await ctx.pool.query(`SELECT * FROM invoices WHERE id::text = $1 AND company_id = $2`, [id, run.company_id])).rows[0];
  if (!row) throw new Error("invoice_not_found");
  return row;
}

async function resolvePayment(run, context, config) {
  const id = resolveTemplate(config.payment_id || context.payment?.id || (run.subject_type === "payment" ? run.subject_id : ""), context);
  if (!id) throw new Error("payment_required");
  const row = (await ctx.pool.query(`SELECT * FROM payment_records WHERE id::text = $1 AND company_id = $2`, [id, run.company_id])).rows[0];
  if (!row) throw new Error("payment_not_found");
  return row;
}

async function resolveServicePlan(run, context, config) {
  const id = resolveTemplate(config.service_plan_id || context.servicePlan?.id || (run.subject_type === "service_plan" ? run.subject_id : ""), context);
  if (!id) throw new Error("service_plan_required");
  const row = (await ctx.pool.query(`SELECT * FROM service_plans WHERE id::text = $1 AND company_id = $2`, [id, run.company_id])).rows[0];
  if (!row) throw new Error("service_plan_not_found");
  return row;
}

function quotePayload(row) {
  return { quote_id: row.id, contact_id: row.contact_id, status: row.status || "draft", total_cents: row.total_cents || 0, subtotal_cents: row.total_cents || 0, line_item_count: Array.isArray(row.line_items) ? row.line_items.length : 0, expires_at: row.expires_at || null };
}

function invoicePayload(row) {
  return { invoice_id: row.id, contact_id: row.contact_id || null, quote_id: row.quote_id || null, job_id: row.job_id || null, status: row.status, total_cents: row.total_cents || 0, currency: row.currency || "usd", due_at: row.due_at || null };
}

function paymentPayload(row) {
  return { payment_id: row.id, contact_id: row.contact_id || null, service_plan_id: row.service_plan_id || null, amount_cents: row.amount_cents || 0, currency: row.currency || "usd", status: row.status, stripe_payment_intent_id: row.stripe_payment_intent_id || null, stripe_invoice_id: row.stripe_invoice_id || null, stripe_subscription_id: row.stripe_subscription_id || null };
}

function servicePlanPayload(row) {
  return { service_plan_id: row.id, contact_id: row.contact_id || null, status: row.status, price_cents: row.price_cents || 0, currency: row.currency || "usd", billing_interval: row.billing_interval, billing_interval_count: row.billing_interval_count, service_interval: row.service_interval, service_interval_count: row.service_interval_count, first_service_date: row.first_service_date || null, last_serviced_at: row.last_service_date || null, next_service_date: row.next_service_date || null, stripe_subscription_id: row.stripe_subscription_id || null, subscription_status: row.stripe_subscription_status || null };
}

async function emitFinancialEvent(run, node, eventType, subjectType, subjectId, payload) {
  await emitAutomationEvent({
    companyId: run.company_id,
    eventType,
    subjectType,
    subjectId,
    source: "automation",
    dedupeKey: `${eventType}:${subjectId}:${run.id}:${node.id}`,
    payload: automationPayload(run, node, payload)
  });
}

async function emitQuoteChangeEvents(run, node, before, after) {
  const changed = diffFields(before, after, ["title", "notes", "status", "total_cents", "contact_id", "expires_at"]);
  if (!changed.length && JSON.stringify(before.line_items || []) === JSON.stringify(after.line_items || [])) return;
  await emitFinancialEvent(run, node, "quote.updated", "quote", after.id, { ...quotePayload(after), changed_fields: changed });
  if (before.status !== after.status) {
    await emitFinancialEvent(run, node, "quote.status_changed", "quote", after.id, { ...quotePayload(after), old_status: before.status, new_status: after.status });
    const statusEvent = { sent: "quote.sent", accepted: "quote.accepted", declined: "quote.declined", expired: "quote.expired" }[after.status];
    if (statusEvent) await emitFinancialEvent(run, node, statusEvent, "quote", after.id, quotePayload(after));
  }
  if (before.total_cents !== after.total_cents) await emitFinancialEvent(run, node, "quote.total_changed", "quote", after.id, { ...quotePayload(after), old_total_cents: before.total_cents, new_total_cents: after.total_cents });
  if (before.contact_id !== after.contact_id) await emitFinancialEvent(run, node, "quote.contact_changed", "quote", after.id, { ...quotePayload(after), old_contact_id: before.contact_id, new_contact_id: after.contact_id });
  const beforeItems = JSON.stringify(before.line_items || []);
  const afterItems = JSON.stringify(after.line_items || []);
  if (beforeItems !== afterItems) {
    await emitFinancialEvent(run, node, "quote.line_items_changed", "quote", after.id, quotePayload(after));
    const beforeCount = Array.isArray(before.line_items) ? before.line_items.length : 0;
    const afterCount = Array.isArray(after.line_items) ? after.line_items.length : 0;
    if (afterCount > beforeCount) await emitFinancialEvent(run, node, "quote.line_item_added", "quote", after.id, quotePayload(after));
    if (afterCount < beforeCount) await emitFinancialEvent(run, node, "quote.line_item_removed", "quote", after.id, quotePayload(after));
  }
}

async function emitServicePlanChangeEvents(run, node, before, after) {
  const changed = diffFields(before, after, ["status", "price_cents", "billing_interval", "billing_interval_count", "service_interval", "service_interval_count", "first_service_date", "next_service_date"]);
  if (!changed.length) return;
  await emitFinancialEvent(run, node, "service_plan.updated", "service_plan", after.id, { ...servicePlanPayload(after), changed_fields: changed });
  const eventMap = { price_cents: "service_plan.price_changed", billing_interval: "service_plan.billing_interval_changed", billing_interval_count: "service_plan.billing_interval_changed", service_interval: "service_plan.service_interval_changed", service_interval_count: "service_plan.service_interval_changed", first_service_date: "service_plan.first_service_date_changed", next_service_date: "service_plan.next_service_changed" };
  for (const changedField of changed) {
    const eventType = eventMap[changedField.field];
    if (eventType) await emitFinancialEvent(run, node, eventType, "service_plan", after.id, { ...servicePlanPayload(after), changed_fields: [changedField] });
  }
}

function diffFields(before, after, fields) {
  return fields.filter((field) => JSON.stringify(before?.[field] ?? null) !== JSON.stringify(after?.[field] ?? null))
    .map((field) => ({ field, old_value: before?.[field] ?? null, new_value: after?.[field] ?? null }));
}

function serviceIntervalDays(interval, count) {
  const n = Math.max(1, Number(count || 1));
  const key = String(interval || "month").toLowerCase();
  if (key.startsWith("day")) return n;
  if (key.startsWith("week")) return n * 7;
  if (key.startsWith("year")) return n * 365;
  return n * 30;
}

function addDaysISO(dateInput, days) {
  const d = new Date(dateInput);
  d.setUTCDate(d.getUTCDate() + Number(days || 0));
  return d.toISOString().slice(0, 10);
}

async function executeRouteCreate(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:route_id`);
  if (existing) {
    const route = await loadRouteContext(run.company_id, existing);
    if (route?.exists) return { route_id: existing, reused: true };
  }
  const context = await buildRunContext(run);
  const assigned = config.assigned_user_id ? await resolveActiveCompanyUser(run.company_id, resolveTemplate(config.assigned_user_id, context)) : null;
  const id = randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO field_routes(id, company_id, name, assigned_user_id, scheduled_date, status, created_by_user_id)
     VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [id, run.company_id, resolveTemplate(config.name || "Automation Route", context), assigned, config.scheduled_date || null, config.scheduled_date ? "scheduled" : "draft", run.manual_started_by_user_id || null]
  );
  await setRunVariable(run.id, `idempotency:${node.id}:route_id`, id);
  await emitRouteEvent(run, node, "route.created", rows[0], {});
  if (assigned) await emitRouteEvent(run, node, "route.assigned", rows[0], { employee_id: assigned });
  if (rows[0].scheduled_date) await emitRouteEvent(run, node, "route.scheduled", rows[0], {});
  return { route_id: id, status: rows[0].status, assigned_user_id: assigned };
}

async function executeRouteDelete(run, node, config) {
  if (config.confirm_delete !== true) throw new Error("confirm_delete_required");
  const route = await resolveRoute(run.company_id, config.route_id || run.subject_id);
  await ctx.pool.query(`DELETE FROM field_routes WHERE id = $1 AND company_id = $2`, [route.id, run.company_id]);
  await emitRouteEvent(run, node, "route.deleted", route, {});
  return { route_id: route.id, deleted: true };
}

async function executeRouteAddStop(run, node, config) {
  const context = await buildRunContext(run);
  const route = await resolveRoute(run.company_id, config.route_id || context.route?.id || run.subject_id);
  return insertRouteStop(run, node, route, resolveConfig(config, context));
}

async function executeRouteAddPin(run, node, config) {
  const context = await buildRunContext(run);
  const pin = await resolveMapPin(run.company_id, config.pin_id || context.map?.id || run.subject_id, context);
  const route = await resolveRoute(run.company_id, config.route_id || context.route?.id);
  return insertRouteStop(run, node, route, { pin_id: pin.id, latitude: pin.latitude, longitude: pin.longitude, address: pin.address, contact_id: pin.contact_id || null });
}

async function executeRouteAddContact(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const contact = await loadContactContext(run.company_id, contactId);
  const route = await resolveRoute(run.company_id, config.route_id || context.route?.id);
  if (contact.lat == null || contact.lng == null) throw new Error("contact_coordinates_required");
  return insertRouteStop(run, node, route, { contact_id: contactId, latitude: contact.lat, longitude: contact.lng, address: contact.address || "" });
}

async function executeRouteAddJob(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const route = await resolveRoute(run.company_id, config.route_id || context.route?.id);
  if (!job.contact_id) throw new Error("job_contact_required");
  const contact = await loadContactContext(run.company_id, job.contact_id);
  if (contact.lat == null || contact.lng == null) throw new Error("job_contact_coordinates_required");
  return insertRouteStop(run, node, route, { job_id: job.id, contact_id: job.contact_id, latitude: contact.lat, longitude: contact.lng, address: contact.address || "" });
}

async function executeRouteRemoveStop(run, node, config) {
  const stop = await resolveRouteStop(run.company_id, config.stop_id || run.subject_id);
  await ctx.pool.query(`DELETE FROM field_route_stops WHERE id = $1 AND company_id = $2`, [stop.id, run.company_id]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "route.stop_removed", subjectType: "route_stop", subjectId: stop.id, source: "automation", payload: automationPayload(run, node, { route_id: stop.route_id, route_stop_id: stop.id }) });
  return { route_id: stop.route_id, route_stop_id: stop.id, removed: true };
}

async function executeRouteAssignUser(run, node, config) {
  const route = await resolveRoute(run.company_id, config.route_id || run.subject_id);
  const userId = await resolveActiveCompanyUser(run.company_id, config.assigned_user_id);
  const { rows } = await ctx.pool.query(`UPDATE field_routes SET assigned_user_id = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [route.id, run.company_id, userId]);
  await emitRouteEvent(run, node, "route.assigned", rows[0], { previous_assigned_user_id: route.assigned_user_id });
  return { route_id: route.id, assigned_user_id: userId };
}

async function executeRouteSetDate(run, node, config) {
  const route = await resolveRoute(run.company_id, config.route_id || run.subject_id);
  const { rows } = await ctx.pool.query(`UPDATE field_routes SET scheduled_date = $3::date, status = CASE WHEN status = 'draft' THEN 'scheduled' ELSE status END, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [route.id, run.company_id, config.scheduled_date || null]);
  await emitRouteEvent(run, node, "route.updated", rows[0], { changed_fields: [{ field: "scheduled_date", old_value: route.scheduled_date, new_value: rows[0].scheduled_date }] });
  if (rows[0].scheduled_date) await emitRouteEvent(run, node, "route.scheduled", rows[0], {});
  return { route_id: route.id, scheduled_date: rows[0].scheduled_date };
}

async function executeRouteOptimize(run, node, config) {
  const route = await resolveRoute(run.company_id, config.route_id || run.subject_id);
  const stops = (await ctx.pool.query(`SELECT * FROM field_route_stops WHERE route_id = $1 AND company_id = $2 ORDER BY sort_order ASC, created_at ASC`, [route.id, run.company_id])).rows;
  const ordered = optimizeStops(stops);
  if (run.dry_run) return { route_id: route.id, would_order_stop_ids: ordered.map((s) => s.id), estimated_distance_miles: routeDistanceMiles(ordered) };
  for (let i = 0; i < ordered.length; i++) await ctx.pool.query(`UPDATE field_route_stops SET sort_order = $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [ordered[i].id, run.company_id, i]);
  await emitRouteEvent(run, node, "route.reordered", route, { ordered_stop_ids: ordered.map((s) => s.id), estimated_distance_miles: routeDistanceMiles(ordered) });
  return { route_id: route.id, ordered_stop_ids: ordered.map((s) => s.id), estimated_distance_miles: routeDistanceMiles(ordered) };
}

async function executeRouteMarkStarted(run, node, config) {
  const route = await resolveRoute(run.company_id, config.route_id || run.subject_id);
  const { rows } = await ctx.pool.query(`UPDATE field_routes SET status = 'started', started_at = COALESCE(started_at, now()), updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [route.id, run.company_id]);
  await emitRouteEvent(run, node, "route.started", rows[0], {});
  return { route_id: route.id, status: rows[0].status };
}

async function executeRouteMarkCompleted(run, node, config) {
  const route = await resolveRoute(run.company_id, config.route_id || run.subject_id);
  const { rows } = await ctx.pool.query(`UPDATE field_routes SET status = 'completed', completed_at = COALESCE(completed_at, now()), updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [route.id, run.company_id]);
  await emitRouteEvent(run, node, "route.completed", rows[0], {});
  return { route_id: route.id, status: rows[0].status };
}

async function executeRouteCompleteStop(run, node, config) {
  return updateRouteStopStatus(run, node, config.stop_id || run.subject_id, "completed", config.notes);
}

async function executeRouteSkipStop(run, node, config) {
  return updateRouteStopStatus(run, node, config.stop_id || run.subject_id, "skipped", config.notes);
}

async function executeEmployeeUpdateRole(run, node, config) {
  if (config.confirm_sensitive_change !== true) throw new Error("confirm_role_change_required");
  const employee = await resolveEmployee(run.company_id, config.employee_id || run.subject_id);
  if (!["employee", "employer"].includes(config.role)) throw new Error("invalid_role");
  if (employee.role === "employer" && config.role !== "employer") await assertNotLastEmployer(run.company_id, employee.id);
  const { rows } = await ctx.pool.query(`UPDATE users SET role = $3 WHERE id = $1 AND company_id = $2 RETURNING id, email, role, display_name, deleted_at`, [employee.id, run.company_id, config.role]);
  await emitEmployeeEvent(run, node, "employee.role_changed", rows[0], { old_role: employee.role, new_role: rows[0].role });
  return { employee_id: employee.id, old_state: { role: employee.role }, new_state: { role: rows[0].role } };
}

async function executeEmployeeDeactivate(run, node, config) {
  if (config.confirm_deactivate !== true) throw new Error("confirm_deactivate_required");
  const employee = await resolveEmployee(run.company_id, config.employee_id || run.subject_id);
  if (employee.role === "employer") await assertNotLastEmployer(run.company_id, employee.id);
  const { rows } = await ctx.pool.query(`UPDATE users SET deleted_at = COALESCE(deleted_at, now()), deleted_by = $3 WHERE id = $1 AND company_id = $2 RETURNING id, email, role, display_name, deleted_at`, [employee.id, run.company_id, run.manual_started_by_user_id || null]);
  await emitEmployeeEvent(run, node, "employee.deactivated", rows[0], {});
  await emitEmployeeEvent(run, node, "employee.removed", rows[0], {});
  return { employee_id: employee.id, old_state: { active: !employee.deleted_at }, new_state: { active: false } };
}

async function executeEmployeeReactivate(run, node, config) {
  const employee = await resolveEmployee(run.company_id, config.employee_id || run.subject_id, { allowInactive: true });
  const { rows } = await ctx.pool.query(`UPDATE users SET deleted_at = NULL, deleted_by = NULL WHERE id = $1 AND company_id = $2 RETURNING id, email, role, display_name, deleted_at`, [employee.id, run.company_id]);
  await emitEmployeeEvent(run, node, "employee.reactivated", rows[0], {});
  return { employee_id: employee.id, old_state: { active: !employee.deleted_at }, new_state: { active: true } };
}

async function executeEmployeeSendPush(run, node, config) {
  const employee = await resolveEmployee(run.company_id, config.employee_id || run.subject_id);
  return executePushNotification(run, node, { title: config.title || "WolfCRM", body: config.body || "", user_ids: [employee.id] });
}

async function executeEmployeeSendInternalMessage(run, node, config) {
  const employee = await resolveEmployee(run.company_id, config.employee_id || run.subject_id);
  return executeInternalDm(run, node, { ...config, recipient_user_id: employee.id });
}

async function executeEmployeeCreateTask(run, node, config) {
  const employee = await resolveEmployee(run.company_id, config.employee_id || run.subject_id);
  return executeTaskCreate(run, node, { ...config, assigned_user_id: employee.id, title: config.title || "Employee follow-up" });
}

async function executeTimeClockCreateReviewTask(run, node, config) {
  const entry = await resolveTimeEntry(run.company_id, config.time_entry_id || run.subject_id);
  return executeTaskCreate(run, node, { title: config.title || "Review time entry", notes: config.body || entry.review_reason || "", assigned_user_id: await resolveCompanyUser(run.company_id, "") });
}

async function executeTimeClockSendEmployeeReminder(run, node, config) {
  const entry = await resolveTimeEntry(run.company_id, config.time_entry_id || run.subject_id);
  return executeInternalDm(run, node, { recipient_user_id: entry.user_id, body: config.body || "Please review your time clock." });
}

async function executeTimeClockNotifyManager(run, node, config) {
  return executePushNotification(run, node, { title: config.title || "Time Clock", body: config.body || "A time entry needs attention." });
}

async function executeTimeClockFlagForReview(run, node, config) {
  const entry = await resolveTimeEntry(run.company_id, config.time_entry_id || run.subject_id);
  const reason = config.review_reason || "Flagged by automation";
  const { rows } = await ctx.pool.query(`UPDATE time_clock_entries SET needs_review = true, review_reason = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [entry.id, run.company_id, reason]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "time_clock.shift_updated", subjectType: "time_entry", subjectId: entry.id, source: "automation", payload: automationPayload(run, node, { time_entry_id: entry.id, employee_id: entry.user_id, needs_review: true, review_reason: reason }) });
  return { time_entry_id: entry.id, needs_review: rows[0].needs_review, review_reason: rows[0].review_reason };
}

async function executeTimeClockClearReviewFlag(run, node, config) {
  const entry = await resolveTimeEntry(run.company_id, config.time_entry_id || run.subject_id);
  const { rows } = await ctx.pool.query(`UPDATE time_clock_entries SET needs_review = false, review_reason = NULL, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [entry.id, run.company_id]);
  return { time_entry_id: entry.id, needs_review: rows[0].needs_review };
}

async function executeMeasurementCreateRecord(run, node, config) {
  const existing = await getRunVariable(run.id, `idempotency:${node.id}:measurement_id`);
  if (existing) return { measurement_id: existing, reused: true };
  const owner = await resolveCompanyUser(run.company_id, "");
  const id = randomUUID();
  const points = Array.isArray(config.points) ? config.points : [];
  const { rows } = await ctx.pool.query(`INSERT INTO measurements(id, user_id, name, points, linked_contact_ids, units) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6) RETURNING *`, [id, owner, config.name || "Automation Measurement", JSON.stringify(points), JSON.stringify(config.linked_contact_ids || []), config.units === "meters" ? "meters" : "feet"]);
  await setRunVariable(run.id, `idempotency:${node.id}:measurement_id`, id);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "measurement.created", subjectType: "measurement", subjectId: id, source: "automation", payload: automationPayload(run, node, measurementPayload(rows[0])) });
  if (points.length >= 2) await emitAutomationEvent({ companyId: run.company_id, eventType: "measurement.completed", subjectType: "measurement", subjectId: id, source: "automation", payload: automationPayload(run, node, measurementPayload(rows[0])) });
  return { measurement_id: id, distance: pathDistance(points), area: polygonAreaApprox(points) };
}

async function executeMeasurementUpdateLabel(run, node, config) {
  const measurement = await resolveMeasurement(run.company_id, config.measurement_id || run.subject_id);
  const { rows } = await ctx.pool.query(`UPDATE measurements SET name = $3, updated_at = now() WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2) RETURNING *`, [measurement.id, run.company_id, config.name || measurement.name]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "measurement.updated", subjectType: "measurement", subjectId: measurement.id, source: "automation", payload: automationPayload(run, node, measurementPayload(rows[0])) });
  return { measurement_id: measurement.id, name: rows[0].name };
}

async function executeMeasurementLinkContact(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const measurement = await resolveMeasurement(run.company_id, config.measurement_id || run.subject_id);
  const ids = Array.isArray(measurement.linked_contact_ids) ? measurement.linked_contact_ids.map(String) : [];
  if (!ids.includes(String(contactId))) ids.push(String(contactId));
  const { rows } = await ctx.pool.query(`UPDATE measurements SET linked_contact_ids = $3::jsonb, updated_at = now() WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE company_id = $2) RETURNING *`, [measurement.id, run.company_id, JSON.stringify(ids)]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "measurement.linked_to_contact", subjectType: "measurement", subjectId: measurement.id, source: "automation", payload: automationPayload(run, node, { ...measurementPayload(rows[0]), contact_id: contactId }) });
  return { measurement_id: measurement.id, contact_id: contactId };
}

async function executeJobCreate(run, node, config) {
  const existingId = await getRunVariable(run.id, `idempotency:${node.id}:job_id`);
  if (existingId) {
    const existing = await loadSubject(run.company_id, "job", existingId);
    if (existing) return { job_id: existingId, reused: true };
  }
  const context = await buildRunContext(run);
  const owner = await resolveCompanyUser(run.company_id, config.assigned_user_id);
  const id = randomUUID();
  const title = resolveTemplate(config.title || "Automation job", context);
  const start = resolveDateExpression(config.start_at || config.start || "", context) || new Date();
  const end = resolveDateExpression(config.end_at || config.end || "", context) || new Date(start.getTime() + 3600000);
  const contactId = config.contact_id ? resolveTemplate(config.contact_id, context) : (run.subject_type === "contact" ? run.subject_id : null);
  if (contactId) await validateSubject(run.company_id, "contact", contactId);
  const sales = await resolveCompanyUsers(run.company_id, config.sales_user_ids || [owner]);
  const workers = await resolveCompanyUsers(run.company_id, config.worker_user_ids || []);
  const serviceItems = normalizeServiceItems(resolveConfig(config.service_items || [], context));
  const { rows } = await ctx.pool.query(
    `INSERT INTO schedule_events(id, user_id, company_id, created_by, title, start_at, end_at, color, notes, contact_id, reminder_minutes, services, service_items, price_cents, material_cost_cents, sales_user_ids, worker_user_ids)
     VALUES($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,'[]'::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14::jsonb,$15::jsonb)
     RETURNING *`,
    [id, owner, run.company_id, title, start.toISOString(), end.toISOString(), config.color || "#3478F6", resolveTemplate(config.notes || "", context) || null, contactId, JSON.stringify(serviceItems.map((s) => s.name)), JSON.stringify(serviceItems), intOrNull(config.price_cents), intOrNull(config.material_cost_cents), JSON.stringify(sales), JSON.stringify(workers)]
  );
  await setRunVariable(run.id, `idempotency:${node.id}:job_id`, id);
  await emitJobMutationEvents(run.company_id, null, rows[0], "automation", null, automationPayload(run, node, { job_id: id, contact_id: contactId }));
  await syncAutomationSchedulesForJob(run.company_id, rows[0]);
  return { job_id: id, contact_id: contactId, start: rows[0].start_at, end: rows[0].end_at, price_cents: rows[0].price_cents, service_items: rows[0].service_items };
}

async function executeJobUpdate(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const updates = {};
  const map = { title: "title", notes: "notes", color: "color", contact_id: "contact_id", price_cents: "price_cents", material_cost_cents: "material_cost_cents" };
  for (const [cfg, col] of Object.entries(map)) if (config[cfg] != null) updates[col] = resolveTemplate(config[cfg], context);
  if (config.start_at || config.start) updates.start_at = resolveDateExpression(config.start_at || config.start, context)?.toISOString();
  if (config.end_at || config.end) updates.end_at = resolveDateExpression(config.end_at || config.end, context)?.toISOString();
  if (config.service_items != null) updates.service_items = normalizeServiceItems(resolveConfig(config.service_items, context));
  if (config.worker_user_ids != null) updates.worker_user_ids = await resolveCompanyUsers(run.company_id, config.worker_user_ids);
  if (config.sales_user_ids != null) updates.sales_user_ids = await resolveCompanyUsers(run.company_id, config.sales_user_ids);
  return updateJobRow(run, node, job, updates);
}

async function executeJobReschedule(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const start = resolveDateExpression(config.start_at || config.start || "", context);
  if (!start) throw new Error("job_start_required");
  const duration = new Date(job.end_at).getTime() - new Date(job.start_at).getTime();
  const end = config.preserve_duration !== false ? new Date(start.getTime() + Math.max(duration, 0)) : (resolveDateExpression(config.end_at || config.end || "", context) || new Date(start.getTime() + Math.max(duration, 3600000)));
  return updateJobRow(run, node, job, { start_at: start.toISOString(), end_at: end.toISOString() });
}

async function executeJobDelete(run, node, config) {
  if (config.confirm_delete !== true) throw new Error("confirm_delete_required");
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  await ctx.pool.query(`DELETE FROM schedule_events WHERE id = $1 AND company_id = $2`, [job.id, run.company_id]);
  await cancelScheduledForSubject(run.company_id, "job", job.id, ["job.start_time_reached", "job.overdue", "job.relative_time"]);
  await emitAutomationEvent({ companyId: run.company_id, eventType: "job.deleted", subjectType: "job", subjectId: job.id, source: "automation", payload: automationPayload(run, node, { job_id: job.id, contact_id: job.contact_id }) });
  return { job_id: job.id, deleted: true };
}

async function executeJobMarkCompleted(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  return updateJobRow(run, node, job, { finished_at: new Date().toISOString(), finished_by: await resolveCompanyUser(run.company_id, "") });
}

async function executeJobReopen(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  return updateJobRow(run, node, job, { finished_at: null, finished_by: null });
}

async function executeJobSetStart(run, node, config) { return executeJobUpdate(run, node, { job_id: config.job_id, start_at: config.start_at }); }
async function executeJobSetEnd(run, node, config) { return executeJobUpdate(run, node, { job_id: config.job_id, end_at: config.end_at }); }
async function executeJobSetPrice(run, node, config) { return executeJobUpdate(run, node, { job_id: config.job_id, price_cents: config.price_cents }); }
async function executeJobSetMaterialCost(run, node, config) { return executeJobUpdate(run, node, { job_id: config.job_id, material_cost_cents: config.material_cost_cents }); }
async function executeJobSetColor(run, node, config) { return executeJobUpdate(run, node, { job_id: config.job_id, color: config.color }); }
async function executeJobSetContact(run, node, config) { return executeJobUpdate(run, node, { job_id: config.job_id, contact_id: config.contact_id }); }

async function executeJobAddService(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const next = normalizeServiceItems(job.service_items || []);
  const name = resolveTemplate(config.service || config.name || "", context).trim();
  if (!name) throw new Error("service_required");
  if (!next.some((s) => s.name.toLowerCase() === name.toLowerCase())) next.push({ name, price_cents: intOrNull(config.price_cents) });
  return updateJobRow(run, node, job, { service_items: next });
}

async function executeJobRemoveService(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const name = resolveTemplate(config.service || config.name || "", context).trim().toLowerCase();
  if (!name) throw new Error("service_required");
  return updateJobRow(run, node, job, { service_items: normalizeServiceItems(job.service_items || []).filter((s) => s.name.toLowerCase() !== name) });
}

async function executeJobAssignWorker(run, node, config) { return updateJobUserList(run, node, config, "worker_user_ids", "add"); }
async function executeJobRemoveWorker(run, node, config) { return updateJobUserList(run, node, config, "worker_user_ids", "remove"); }
async function executeJobReplaceWorkers(run, node, config) { return updateJobUserList(run, node, config, "worker_user_ids", "replace"); }
async function executeJobAssignSalesperson(run, node, config) { return updateJobUserList(run, node, config, "sales_user_ids", "add"); }
async function executeJobRemoveSalesperson(run, node, config) { return updateJobUserList(run, node, config, "sales_user_ids", "remove"); }
async function executeJobReplaceSalespeople(run, node, config) { return updateJobUserList(run, node, config, "sales_user_ids", "replace"); }

async function updateJobUserList(run, node, config, field, mode) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const current = Array.isArray(job[field]) ? job[field] : [];
  const ids = await resolveCompanyUsers(run.company_id, mode === "replace" ? (config[field] || []) : [config.user_id]);
  const next = mode === "replace" ? ids : mode === "add" ? [...new Set([...current, ...ids])] : current.filter((id) => !ids.includes(id));
  return updateJobRow(run, node, job, { [field]: next });
}

async function executeJobAddNote(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const note = resolveTemplate(config.notes || config.note || "", context).trim();
  if (!note) throw new Error("note_required");
  return updateJobRow(run, node, job, { notes: [job.notes, note].filter(Boolean).join("\n") });
}

async function executeJobCreateFollowup(run, node, config) {
  const context = await buildRunContext(run);
  const job = await resolveJob(run.company_id, run.subject_id, config.job_id, context);
  const amount = Number(config.amount || 1);
  const unit = config.unit || "weeks";
  const start = addCalendarDuration(new Date(job.start_at), amount, unit);
  const duration = new Date(job.end_at).getTime() - new Date(job.start_at).getTime();
  return executeJobCreate(run, node, {
    title: config.title || job.title,
    start_at: start.toISOString(),
    end_at: new Date(start.getTime() + Math.max(duration, 3600000)).toISOString(),
    contact_id: job.contact_id,
    notes: config.notes || job.notes || "",
    color: job.color,
    service_items: config.copy_services ? job.service_items : [],
    worker_user_ids: config.copy_workers ? job.worker_user_ids : [],
    sales_user_ids: config.copy_salespeople ? job.sales_user_ids : [],
    price_cents: config.copy_price ? job.price_cents : null,
    material_cost_cents: config.copy_price ? job.material_cost_cents : null
  });
}

async function executeFindAvailableSlots(run, _node, config) {
  const context = await buildRunContext(run);
  const start = resolveDateExpression(config.range_start || "now", context) || new Date();
  const end = resolveDateExpression(config.range_end || "tomorrow", context) || new Date(start.getTime() + 7 * 86400000);
  const durationMs = Math.max(15, Number(config.duration_minutes || 60)) * 60000;
  const workers = await resolveCompanyUsers(run.company_id, config.worker_user_ids || []);
  const jobs = (await ctx.pool.query(
    `SELECT id, start_at, end_at, worker_user_ids FROM schedule_events WHERE company_id = $1 AND start_at < $3 AND end_at > $2 AND finished_at IS NULL ORDER BY start_at ASC`,
    [run.company_id, start.toISOString(), end.toISOString()]
  )).rows;
  const slots = [];
  for (let cursor = new Date(start); cursor.getTime() + durationMs <= end.getTime() && slots.length < Number(config.limit || 10); cursor = new Date(cursor.getTime() + 30 * 60000)) {
    const slotEnd = new Date(cursor.getTime() + durationMs);
    const overlaps = jobs.some((job) => {
      if (new Date(job.start_at) >= slotEnd || new Date(job.end_at) <= cursor) return false;
      if (!workers.length) return true;
      const assigned = Array.isArray(job.worker_user_ids) ? job.worker_user_ids : [];
      return workers.some((id) => assigned.includes(id));
    });
    if (!overlaps) slots.push({ start: cursor.toISOString(), end: slotEnd.toISOString(), worker_user_ids: workers });
  }
  return { slots };
}

function boundedLimit(config, fallback = 25) {
  return Math.min(Math.max(0, Number(config.limit || fallback) || fallback), AUTOMATION_LIMITS.maxCollectionOutputItems);
}

async function executeContactsSearch(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["company_id = $1", "deleted_at IS NULL"];
  const params = [run.company_id];
  const tags = normalizeTags(resolveRawValue(config.tags || [], context));
  if (tags.length) {
    params.push(tags);
    clauses.push(`tags ?| $${params.length}::text[]`);
  }
  if (config.source) {
    params.push(resolveTemplate(config.source, context));
    clauses.push(`source = $${params.length}`);
  }
  if (config.min_value_cents != null) {
    params.push(Number(resolveTemplate(config.min_value_cents, context)) || 0);
    clauses.push(`COALESCE(value,0) >= $${params.length}`);
  }
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(
    `SELECT id, name, phone, email, address, tags, source, job_type, value, created_at, updated_at
       FROM contacts WHERE ${clauses.join(" AND ")}
      ORDER BY updated_at DESC LIMIT $${params.length}`,
    params
  )).rows;
  return { contacts: rows, items: rows, count: rows.length };
}

async function executeJobsSearch(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["company_id = $1"];
  const params = [run.company_id];
  if (config.contact_id) { params.push(resolveTemplate(config.contact_id, context)); clauses.push(`contact_id::text = $${params.length}`); }
  if (config.start_after) { params.push(resolveDateExpression(config.start_after, context)?.toISOString()); clauses.push(`start_at >= $${params.length}::timestamptz`); }
  if (config.start_before) { params.push(resolveDateExpression(config.start_before, context)?.toISOString()); clauses.push(`start_at <= $${params.length}::timestamptz`); }
  if (config.completed != null) clauses.push(config.completed ? "finished_at IS NOT NULL" : "finished_at IS NULL");
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(
    `SELECT id, contact_id, title, start_at, end_at, finished_at, price_cents, worker_user_ids, sales_user_ids, service_items
       FROM schedule_events WHERE ${clauses.join(" AND ")}
      ORDER BY start_at DESC LIMIT $${params.length}`,
    params
  )).rows;
  return { jobs: rows, items: rows, count: rows.length };
}

async function executeTasksSearch(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["u.company_id = $1"];
  const params = [run.company_id];
  if (config.contact_id) { params.push(resolveTemplate(config.contact_id, context)); clauses.push(`tt.contact_id::text = $${params.length}`); }
  if (config.completed != null) { params.push(!!config.completed); clauses.push(`tt.completed = $${params.length}`); }
  if (config.overdue === true) clauses.push(`tt.completed = false AND tt.due_date IS NOT NULL AND tt.due_date < now()`);
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(
    `SELECT tt.id, tt.user_id, tt.contact_id, tt.title, tt.notes, tt.due_date, tt.completed, tt.created_at, tt.updated_at
       FROM todo_tasks tt JOIN users u ON u.id = tt.user_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY tt.updated_at DESC LIMIT $${params.length}`,
    params
  )).rows;
  return { tasks: rows, items: rows, count: rows.length };
}

async function executeMapSearchPins(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["u.company_id = $1"];
  const params = [run.company_id];
  if (config.status) { params.push(resolveTemplate(config.status, context)); clauses.push(`p.status = $${params.length}`); }
  if (config.list_id) { params.push(resolveTemplate(config.list_id, context)); clauses.push(`p.list_id::text = $${params.length}`); }
  if (config.has_contact != null) clauses.push(config.has_contact ? "p.contact_id IS NOT NULL" : "p.contact_id IS NULL");
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(
    `SELECT p.id, p.contact_id, p.address, p.lat, p.lng, p.status, p.list_id, p.source, p.last_visit_at, p.last_knock_at, p.created_at, p.updated_at
       FROM map_pins p JOIN users u ON u.id = p.user_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY p.updated_at DESC LIMIT $${params.length}`,
    params
  )).rows;
  return { pins: rows, items: rows, count: rows.length };
}

async function executeRouteGetStops(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const routeId = resolveTemplate(config.route_id || context.route?.id || context.event?.payload?.route_id || run.subject_id || "", context);
  if (!routeId) throw new Error("route_required");
  const clauses = ["route_id::text = $1", "company_id = $2"];
  const params = [routeId, run.company_id];
  const filter = config.filter || "all";
  if (filter === "completed") clauses.push("status = 'completed'");
  if (filter === "skipped") clauses.push("status = 'skipped'");
  if (filter === "remaining") clauses.push("status NOT IN ('completed','skipped')");
  const rows = (await ctx.pool.query(
    `SELECT id, route_id, pin_id, contact_id, job_id, latitude, longitude, address, sort_order, status, arrived_at, completed_at, notes
       FROM field_route_stops WHERE ${clauses.join(" AND ")} ORDER BY sort_order ASC, created_at ASC`,
    params
  )).rows;
  return { stops: capCollection(rows), items: capCollection(rows), count: rows.length };
}

async function executeQuotesSearch(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["company_id = $1"];
  const params = [run.company_id];
  if (config.status) { params.push(resolveTemplate(config.status, context)); clauses.push(`status = $${params.length}`); }
  if (config.contact_id) { params.push(resolveTemplate(config.contact_id, context)); clauses.push(`contact_id::text = $${params.length}`); }
  if (config.min_total_cents != null) { params.push(Number(resolveTemplate(config.min_total_cents, context)) || 0); clauses.push(`total_cents >= $${params.length}`); }
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(`SELECT id, contact_id, title, status, subtotal_cents, total_cents, expires_at, created_at, updated_at FROM quotes WHERE ${clauses.join(" AND ")} ORDER BY updated_at DESC LIMIT $${params.length}`, params)).rows;
  return { quotes: rows, items: rows, count: rows.length };
}

async function executePaymentsSearch(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["company_id = $1"];
  const params = [run.company_id];
  if (config.status) { params.push(resolveTemplate(config.status, context)); clauses.push(`status = $${params.length}`); }
  if (config.contact_id) { params.push(resolveTemplate(config.contact_id, context)); clauses.push(`contact_id::text = $${params.length}`); }
  if (config.service_plan_id) { params.push(resolveTemplate(config.service_plan_id, context)); clauses.push(`service_plan_id::text = $${params.length}`); }
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(`SELECT id, contact_id, service_plan_id, amount_cents, currency, status, created_at, updated_at FROM payment_records WHERE ${clauses.join(" AND ")} ORDER BY created_at DESC LIMIT $${params.length}`, params)).rows;
  return { payments: rows, items: rows, count: rows.length };
}

async function executeServicePlansSearch(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const clauses = ["company_id = $1"];
  const params = [run.company_id];
  if (config.status) { params.push(resolveTemplate(config.status, context)); clauses.push(`status = $${params.length}`); }
  if (config.contact_id) { params.push(resolveTemplate(config.contact_id, context)); clauses.push(`contact_id::text = $${params.length}`); }
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(`SELECT id, contact_id, plan_name, status, price_cents, billing_interval, service_interval, first_service_date, last_serviced_at, next_service_date, service_count FROM service_plans WHERE ${clauses.join(" AND ")} ORDER BY updated_at DESC LIMIT $${params.length}`, params)).rows;
  return { service_plans: rows, items: rows, count: rows.length };
}

async function executeEmployeesSearch(run, _node, config) {
  const clauses = ["company_id = $1"];
  const params = [run.company_id];
  if (config.role && config.role !== "any") { params.push(config.role); clauses.push(`role = $${params.length}`); }
  if (config.active != null) { params.push(!!config.active); clauses.push(`active = $${params.length}`); }
  params.push(boundedLimit(config));
  const rows = (await ctx.pool.query(`SELECT id, name, email, role, active, created_at, updated_at FROM users WHERE ${clauses.join(" AND ")} ORDER BY name ASC LIMIT $${params.length}`, params)).rows;
  return { employees: rows, items: rows, count: rows.length };
}

async function executeCollectionFilter(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const items = resolveCollection(config.collection, context);
  const out = items.filter((item, index) => evaluateCondition(config.condition || {}, { ...context, item, item_index: index, iteration: { ...(context.iteration || {}), item, index } }));
  return { items: capCollection(out), count: out.length };
}

async function executeCollectionMap(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const items = resolveCollection(config.collection, context);
  const mappings = parseJsonObject(config.mappings || {});
  const out = items.map((item, index) => resolveConfig(mappings, { ...context, item, item_index: index, iteration: { ...(context.iteration || {}), item, index } }));
  return { items: capCollection(out), count: out.length };
}

async function executeCollectionSort(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const dir = config.direction === "desc" ? -1 : 1;
  const type = config.value_type || "string";
  const items = resolveCollection(config.collection, context).map((item, index) => ({ item, index }));
  items.sort((a, b) => {
    const av = getPath(a.item, config.field || "id");
    const bv = getPath(b.item, config.field || "id");
    const left = type === "number" ? Number(av || 0) : type === "date" ? new Date(av || 0).getTime() : String(av ?? "");
    const right = type === "number" ? Number(bv || 0) : type === "date" ? new Date(bv || 0).getTime() : String(bv ?? "");
    if (left === right) return a.index - b.index;
    return left > right ? dir : -dir;
  });
  const out = items.map((entry) => entry.item);
  return { items: out, count: out.length };
}

async function executeCollectionLimit(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const items = resolveCollection(config.collection, context, { maxItems: boundedLimit(config) });
  return { items, count: items.length };
}

async function executeCollectionFirst(run, _node, config, scopeKey = "root") {
  const items = resolveCollection(config.collection, await buildRunContext(run, { scopeKey }));
  return { item: items[0] || null, exists: items.length > 0 };
}

async function executeCollectionLast(run, _node, config, scopeKey = "root") {
  const items = resolveCollection(config.collection, await buildRunContext(run, { scopeKey }));
  return { item: items[items.length - 1] || null, exists: items.length > 0 };
}

async function executeCollectionCount(run, _node, config, scopeKey = "root") {
  const items = resolveCollection(config.collection, await buildRunContext(run, { scopeKey }));
  return { count: items.length };
}

async function executeCollectionUnique(run, _node, config, scopeKey = "root") {
  const items = resolveCollection(config.collection, await buildRunContext(run, { scopeKey }));
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = config.identity_field ? getPath(item, config.identity_field) : item;
    const stable = JSON.stringify(key);
    if (seen.has(stable)) continue;
    seen.add(stable);
    out.push(item);
  }
  return { items: out, count: out.length };
}

async function executeCollectionConcat(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const collections = Array.isArray(config.collections) ? config.collections : [config.collection_a, config.collection_b].filter(Boolean);
  const out = collections.flatMap((entry) => resolveCollection(entry, context));
  return { items: capCollection(out), count: Math.min(out.length, AUTOMATION_LIMITS.maxCollectionOutputItems), truncated: out.length > AUTOMATION_LIMITS.maxCollectionOutputItems };
}

async function executeCollectionFlatten(run, _node, config, scopeKey = "root") {
  const items = resolveCollection(config.collection, await buildRunContext(run, { scopeKey }));
  const out = items.flatMap((item) => Array.isArray(item) ? item : [item]);
  return { items: capCollection(out), count: out.length };
}

async function executeCollectionContains(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const items = resolveCollection(config.collection, context);
  const value = resolveRawValue(config.value, context);
  const found = items.some((item) => looseEqual(config.field ? getPath(item, config.field) : item, value));
  return { result: found };
}

async function executeVariableIncrement(run, _node, config) {
  const name = String(config.name || "").trim();
  if (!name) throw new Error("variable_name_required");
  const amount = Number(config.amount ?? 1) || 0;
  const row = (await ctx.pool.query(
    `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
     ON CONFLICT(run_id, name) DO UPDATE
       SET value = to_jsonb(COALESCE((automation_variables.value #>> '{}')::numeric, 0) + $4::numeric), updated_at = now()
     RETURNING value`,
    [run.id, name, JSON.stringify(amount), amount]
  )).rows[0];
  return { name, value: row.value };
}

async function executeVariableAppend(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const name = String(config.name || "").trim();
  if (!name) throw new Error("variable_name_required");
  const value = safeJsonLimited(resolveRawValue(config.value, context));
  const existing = (await ctx.pool.query(`SELECT value FROM automation_variables WHERE run_id = $1 AND name = $2 FOR UPDATE`, [run.id, name])).rows[0]?.value;
  const list = Array.isArray(existing) ? existing : [];
  const next = config.dedupe && list.some((item) => looseEqual(item, value)) ? list : capCollection([...list, value]);
  await ctx.pool.query(
    `INSERT INTO automation_variables(run_id, name, value) VALUES($1,$2,$3::jsonb)
     ON CONFLICT(run_id, name) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [run.id, name, JSON.stringify(next)]
  );
  return { name, value: next, count: next.length };
}

async function executeObjectGet(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const object = resolveRawValue(config.object, context);
  const path = String(config.path || "");
  if (!isSafeObjectPath(path)) throw new Error("unsafe_object_path");
  return { value: getPath(object || {}, path), exists: getPath(object || {}, path) != null };
}

async function executeObjectBuild(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  return { object: safeJsonLimited(resolveConfig(parseJsonObject(config.mappings || {}), context)) };
}

async function executeCoalesce(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  for (const value of (Array.isArray(config.values) ? config.values : [])) {
    const resolved = resolveRawValue(value, context);
    if (resolved != null && resolved !== "") return { value: resolved };
  }
  return { value: null };
}

async function executeMath(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const a = Number(resolveRawValue(config.a, context) || 0);
  const b = Number(resolveRawValue(config.b, context) || 0);
  const op = config.operation || "add";
  let value = a + b;
  if (op === "subtract") value = a - b;
  if (op === "multiply") value = a * b;
  if (op === "divide") {
    if (b === 0) throw new Error("divide_by_zero");
    value = a / b;
  }
  if (op === "percentage") value = Math.round(a * b / 100);
  if (op === "min") value = Math.min(a, b);
  if (op === "max") value = Math.max(a, b);
  if (op === "round") value = Math.round(a);
  if (op === "floor") value = Math.floor(a);
  if (op === "ceil") value = Math.ceil(a);
  if (op === "absolute") value = Math.abs(a);
  return { value, operation: op };
}

async function executeText(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const op = config.operation || "concat";
  const value = resolveRawValue(config.value, context);
  const text = Array.isArray(value) ? value.map(String) : String(value ?? "");
  if (op === "join") return { value: (Array.isArray(value) ? value : [value]).map((v) => String(v ?? "")).join(config.delimiter ?? ", ") };
  if (op === "uppercase") return { value: String(text).toUpperCase() };
  if (op === "lowercase") return { value: String(text).toLowerCase() };
  if (op === "trim") return { value: String(text).trim() };
  if (op === "replace") return { value: String(text).split(config.find || "").join(config.replace || "") };
  if (op === "substring") return { value: String(text).slice(Number(config.start || 0), config.end == null ? undefined : Number(config.end)) };
  if (op === "split") return { items: String(text).split(config.delimiter ?? ","), count: String(text).split(config.delimiter ?? ",").length };
  if (op === "length") return { value: String(text).length };
  return { value: Array.isArray(value) ? value.join(config.delimiter ?? "") : String(text) + String(resolveRawValue(config.b || "", context) ?? "") };
}

async function executeDateTransform(run, _node, config, scopeKey = "root") {
  const context = await buildRunContext(run, { scopeKey });
  const base = new Date(resolveRawValue(config.value, context) || Date.now());
  if (Number.isNaN(base.getTime())) throw new Error("invalid_date");
  const op = config.operation || "add";
  let value = base;
  if (op === "add") value = addCalendarDuration(base, Number(config.amount || 0), config.unit || "days");
  if (op === "subtract") value = addCalendarDuration(base, -Number(config.amount || 0), config.unit || "days");
  if (op === "start_of_day") value = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth(), base.getUTCDate(), 0, 0, 0));
  if (op === "end_of_day") value = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth(), base.getUTCDate(), 23, 59, 59, 999));
  if (op === "next_weekday") {
    value = new Date(base);
    do { value = addCalendarDuration(value, 1, "days"); } while ([0, 6].includes(value.getUTCDay()));
  }
  if (op === "difference") {
    const other = new Date(resolveRawValue(config.other, context) || Date.now());
    return { value: Math.round((other.getTime() - base.getTime()) / 60000), unit: "minutes" };
  }
  return { value: value.toISOString(), timezone: context.company?.timezone || "UTC" };
}

async function resolveJob(companyId, subjectId, explicitId, context) {
  const jobId = resolveTemplate(explicitId || context.job?.id || subjectId || "", context);
  if (!jobId) throw new Error("job_id_required");
  const job = (await ctx.pool.query(`SELECT * FROM schedule_events WHERE id = $1 AND company_id = $2`, [jobId, companyId])).rows[0];
  if (!job) throw new Error("job_not_found");
  return job;
}

async function updateJobRow(run, node, before, updates) {
  const cols = Object.keys(updates);
  if (!cols.length) return { job_id: before.id, updated: [] };
  const sets = cols.map((key, i) => `${key} = $${i + 3}${["service_items", "worker_user_ids", "sales_user_ids"].includes(key) ? "::jsonb" : ""}`);
  const values = cols.map((key) => ["service_items", "worker_user_ids", "sales_user_ids"].includes(key) ? JSON.stringify(updates[key]) : updates[key]);
  const { rows } = await ctx.pool.query(`UPDATE schedule_events SET ${sets.join(", ")}, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [before.id, run.company_id, ...values]);
  if (!rows.length) throw new Error("job_not_found");
  await emitJobMutationEvents(run.company_id, before, rows[0], "automation", null, automationPayload(run, node, { job_id: before.id, contact_id: rows[0].contact_id }));
  await syncAutomationSchedulesForJob(run.company_id, rows[0]);
  return { job_id: rows[0].id, updated: cols, old_start: before.start_at, new_start: rows[0].start_at, old_end: before.end_at, new_end: rows[0].end_at };
}

async function emitJobMutationEvents(companyId, before, after, source, actorUserId, payload = {}) {
  const jobId = after?.id || before?.id;
  if (!jobId) return;
  const base = { ...payload, job_id: jobId, contact_id: after?.contact_id || before?.contact_id || null };
  if (!before) {
    await emitAutomationEvent({ companyId, eventType: "job.created", subjectType: "job", subjectId: jobId, actorUserId, source, dedupeKey: `job.created:${jobId}`, payload: base });
    await emitAutomationEvent({ companyId, eventType: "job.scheduled", subjectType: "job", subjectId: jobId, actorUserId, source, dedupeKey: `job.scheduled:${jobId}:${after.start_at}:${after.end_at}`, payload: { ...base, start: after.start_at, end: after.end_at } });
    if (source === "automation") await emitAutomationEvent({ companyId, eventType: "job.created_by_automation", subjectType: "job", subjectId: jobId, actorUserId, source, dedupeKey: `job.created_by_automation:${jobId}`, payload: base });
    if (after.contact_id) {
      const count = (await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM schedule_events WHERE company_id = $1 AND contact_id = $2`, [companyId, after.contact_id])).rows[0]?.count || 0;
      await emitAutomationEvent({ companyId, eventType: Number(count) <= 1 ? "job.first_job_for_contact" : "job.repeat_job_for_contact", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, job_count_for_contact: Number(count) } });
    }
    await emitAssignmentEvents(companyId, jobId, "worker", [], jsonArray(after.worker_user_ids), source, actorUserId, base);
    await emitAssignmentEvents(companyId, jobId, "salesperson", [], jsonArray(after.sales_user_ids), source, actorUserId, base);
    return;
  }
  const fields = ["title", "start_at", "end_at", "color", "notes", "contact_id", "price_cents", "material_cost_cents", "service_items", "worker_user_ids", "sales_user_ids", "finished_at"];
  const changed = fields.map((field) => ({ field, old_value: before[field] ?? null, new_value: after[field] ?? null })).filter((f) => JSON.stringify(f.old_value) !== JSON.stringify(f.new_value));
  if (!changed.length) return;
  await emitAutomationEvent({ companyId, eventType: "job.updated", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, changed_fields: changed } });
  await emitAutomationEvent({ companyId, eventType: "job.field_changed", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, changed_fields: changed } });
  if (changed.some((f) => f.field === "start_at" || f.field === "end_at")) {
    await emitAutomationEvent({ companyId, eventType: "job.rescheduled", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, old_start: before.start_at, new_start: after.start_at, old_end: before.end_at, new_end: after.end_at } });
  }
  for (const change of changed) {
    const eventType = jobFieldEventType(change.field, before, after);
    if (eventType) await emitAutomationEvent({ companyId, eventType, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, changed_fields: [change], field: change.field, old_value: change.old_value, new_value: change.new_value } });
  }
  await emitServiceEvents(companyId, jobId, before, after, source, actorUserId, base);
  await emitAssignmentEvents(companyId, jobId, "worker", jsonArray(before.worker_user_ids), jsonArray(after.worker_user_ids), source, actorUserId, base);
  await emitAssignmentEvents(companyId, jobId, "salesperson", jsonArray(before.sales_user_ids), jsonArray(after.sales_user_ids), source, actorUserId, base);
  if (!before.finished_at && after.finished_at) await emitAutomationEvent({ companyId, eventType: "job.completed", subjectType: "job", subjectId: jobId, actorUserId, source, dedupeKey: `job.completed:${jobId}:${after.finished_at}`, payload: { ...base, finished_at: after.finished_at } });
  if (before.finished_at && !after.finished_at) await emitAutomationEvent({ companyId, eventType: "job.reopened", subjectType: "job", subjectId: jobId, actorUserId, source, payload: base });
}

function jobFieldEventType(field, before, after) {
  if (field === "start_at") return "job.start_changed";
  if (field === "end_at") return "job.end_changed";
  if (field === "price_cents") return "job.price_changed";
  if (field === "material_cost_cents") return "job.material_cost_changed";
  if (field === "color") return "job.color_changed";
  if (field === "contact_id") return "job.contact_changed";
  if ((field === "start_at" || field === "end_at") && String(before?.[field]).slice(0, 10) !== String(after?.[field]).slice(0, 10)) return "job.date_changed";
  return null;
}

async function emitServiceEvents(companyId, jobId, before, after, source, actorUserId, base) {
  const oldNames = normalizeServiceItems(before.service_items || before.services || []).map((s) => s.name.toLowerCase());
  const newItems = normalizeServiceItems(after.service_items || after.services || []);
  const newNames = newItems.map((s) => s.name.toLowerCase());
  const added = newItems.filter((s) => !oldNames.includes(s.name.toLowerCase()));
  const removed = normalizeServiceItems(before.service_items || before.services || []).filter((s) => !newNames.includes(s.name.toLowerCase()));
  if (added.length) await emitAutomationEvent({ companyId, eventType: "job.service_added", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, services: added.map((s) => s.name) } });
  if (removed.length) await emitAutomationEvent({ companyId, eventType: "job.service_removed", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, services: removed.map((s) => s.name) } });
  if (added.length || removed.length) await emitAutomationEvent({ companyId, eventType: "job.services_changed", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, added_services: added, removed_services: removed } });
}

async function emitAssignmentEvents(companyId, jobId, kind, beforeIds, afterIds, source, actorUserId, base) {
  const added = afterIds.filter((id) => !beforeIds.includes(id));
  const removed = beforeIds.filter((id) => !afterIds.includes(id));
  const prefix = kind === "worker" ? "worker" : "salesperson";
  if (added.length) await emitAutomationEvent({ companyId, eventType: `job.${prefix}_assigned`, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, [`${prefix}_ids_added`]: added } });
  if (removed.length) await emitAutomationEvent({ companyId, eventType: `job.${prefix}_removed`, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, [`${prefix}_ids_removed`]: removed } });
  if (added.length || removed.length) await emitAutomationEvent({ companyId, eventType: `job.${prefix === "worker" ? "workers" : "salespeople"}_changed`, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, added, removed } });
}

function jsonArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeServiceItems(value) {
  if (!Array.isArray(value)) return normalizeTags(value).map((name) => ({ name, price_cents: null }));
  return value.map((item) => typeof item === "string" ? { name: item, price_cents: null } : { name: String(item?.name || "").trim(), price_cents: intOrNull(item?.price_cents) }).filter((s) => s.name);
}

async function resolveCompanyUsers(companyId, ids) {
  const requested = Array.isArray(ids) ? ids.filter(Boolean).map(String) : [];
  if (!requested.length) return [];
  return (await ctx.pool.query(`SELECT id FROM users WHERE company_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`, [companyId, requested])).rows.map((r) => r.id);
}

function resolveDateExpression(value, context) {
  if (value instanceof Date) return value;
  if (value && typeof value === "object") {
    const basis = value.basis || value.reference || "specific";
    const amount = Number(value.amount || 0);
    const unit = value.unit || "minutes";
    const direction = value.direction || "after";
    let date = basis === "job_start" || basis === "start" ? new Date(context.job?.start_at || context.job?.start || Date.now())
      : basis === "job_end" || basis === "end" ? new Date(context.job?.end_at || context.job?.end || Date.now())
        : basis === "task_due" ? new Date(context.task?.due_date || Date.now())
          : basis === "now" ? new Date()
            : new Date(resolveTemplate(value.value || value.datetime || "", context));
    if (Number.isNaN(date.getTime())) return null;
    if (amount) date = new Date(date.getTime() + (direction === "before" ? -1 : 1) * durationAmountMs(amount, unit));
    return date;
  }
  const text = resolveTemplate(value || "", context).trim();
  if (!text || text === "now") return new Date();
  if (text === "tomorrow") return new Date(Date.now() + 86400000);
  const duration = text.match(/^(\d+)\s+(minute|minutes|hour|hours|day|days|week|weeks)\s+from now$/i);
  if (duration) return new Date(Date.now() + durationAmountMs(Number(duration[1]), duration[2]));
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function addCalendarDuration(date, amount, unit) {
  const next = new Date(date);
  if (String(unit).startsWith("month")) next.setUTCMonth(next.getUTCMonth() + amount);
  else next.setTime(next.getTime() + durationAmountMs(amount, unit));
  return next;
}

async function executeWebhookSend(run, node, config, scopeKey = "root") {
  const existing = await getConfirmedActionEffect(run.id, node.id, scopeKey, "webhook.send");
  if (existing) return { ...(existing.result || {}), idempotent_replay: true };
  const context = await buildRunContext(run, { scopeKey });
  const method = (config.method || "POST").toString().toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) throw new Error("unsupported_method");
  const url = new URL(resolveTemplate(config.url || "", context));
  await assertSafeWebhookUrl(url);
  const headers = Object.fromEntries(Object.entries(resolveConfig(config.headers || {}, context)).filter(([k]) => !/authorization|cookie|token|secret/i.test(k)));
  const idempotencyKey = config.disable_idempotency_key === true ? null : `wolfcrm-auto-${run.id}-${node.id}-${stablePortId(scopeKey)}`;
  await recordActionEffect(run.id, node.id, scopeKey, "webhook.send", "started", { url: url.origin + url.pathname, method });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(15000, Math.max(1000, Number(config.timeout_ms || 8000))));
  try {
    const response = await fetch(url, {
      method,
      headers: { "content-type": "application/json", ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}), ...headers },
      body: ["GET", "DELETE"].includes(method) ? undefined : JSON.stringify(resolveConfig(config.body || {}, context)),
      signal: controller.signal
    });
    const text = (await response.text()).slice(0, 4096);
    if (!response.ok && !config.continue_on_http_error) throw new Error(`webhook_http_${response.status}`);
    const output = { status: response.status, body: text, headers: safeResponseHeaders(response.headers), idempotency_key: idempotencyKey };
    await recordActionEffect(run.id, node.id, scopeKey, "webhook.send", "confirmed", output, String(response.status));
    return output;
  } catch (e) {
    if (e?.name === "AbortError") await recordActionEffect(run.id, node.id, scopeKey, "webhook.send", "outcome_unknown", { reason: "timeout" });
    else await recordActionEffect(run.id, node.id, scopeKey, "webhook.send", "failed", { error: e?.message });
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function assertSafeWebhookUrl(url) {
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("unsupported_protocol");
  const host = url.hostname.toLowerCase();
  if (["localhost", "127.0.0.1", "0.0.0.0", "::1"].includes(host) || host.endsWith(".local")) throw new Error("blocked_host");
  const ipType = net.isIP(host);
  if (ipType && isPrivateIp(host)) throw new Error("blocked_private_network");
}

function isPrivateIp(host) {
  if (host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) return true;
  if (host.startsWith("172.")) {
    const second = Number(host.split(".")[1]);
    return second >= 16 && second <= 31;
  }
  return host === "::1" || host.startsWith("fc") || host.startsWith("fd");
}

function safeResponseHeaders(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) if (!/authorization|cookie|token|secret/i.test(k)) out[k] = v.slice(0, 500);
  return out;
}

async function executeAutomationStart(run, node, config) {
  const automationId = config.automation_id;
  const automation = (await ctx.pool.query(
    `SELECT d.*, v.id AS version_id FROM automation_definitions d JOIN automation_versions v ON v.id = d.active_version_id
      WHERE d.id = $1 AND d.company_id = $2 AND d.status = 'published' AND v.status = 'published'`,
    [automationId, run.company_id]
  )).rows[0];
  if (!automation) throw new Error("child_automation_not_found");
  if (run.depth >= AUTOMATION_LIMITS.maxChildDepth) throw new Error("child_depth_limit");
  const child = await createRun({
    companyId: run.company_id,
    automationId,
    versionId: automation.version_id,
    triggerEventId: run.trigger_event_id,
    subjectType: run.subject_type,
    subjectId: run.subject_id,
    parentRunId: run.id,
    parentNodeId: node.id,
    rootRunId: run.root_run_id || run.id,
    depth: run.depth + 1,
    dryRun: run.dry_run
  });
  setImmediate(() => runAutomation(child.id).catch((e) => console.error("[automations] child run failed", e?.message || e)));
  return { child_run_id: child.id };
}

async function validateSubject(companyId, type, id) {
  if (!id || type === "generic") return true;
  const subject = await loadSubject(companyId, type, id);
  if (!subject) throw new Error("subject_not_found");
  return true;
}

function isRetrySafe(node) {
  return SIDE_EFFECT_FREE_ACTIONS.has(node.config?.action_key) || ["notification.send_push", "webhook.send", "sms.send", "sms.send_mms", "payment.create_request", "payment.create_payment_link"].includes(node.config?.action_key);
}

function classifyErrorCode(code) {
  const value = String(code || "unknown_error");
  if (/missing|not_found|required|invalid|confirmation/.test(value)) return "validation_error";
  if (/permission|scope/.test(value)) return "permission_denied";
  if (/opted_out|dnc/.test(value)) return "recipient_opted_out";
  if (/stripe_not_connected/.test(value)) return "stripe_not_connected";
  if (/rate|quota|budget|limit/.test(value)) return "rate_limited";
  if (/timeout/.test(value)) return "external_timeout";
  if (/5\d\d|unavailable|econnreset|network/.test(value)) return "external_5xx";
  if (/4\d\d|twilio_non_retryable|compliance/.test(value)) return "external_4xx";
  if (/constraint|duplicate/.test(value)) return "database_constraint";
  if (/cancel/.test(value)) return "run_canceled";
  if (/loop|depth/.test(value)) return "loop_protection";
  return "unknown_error";
}

function isRetryableErrorCode(code) {
  const value = String(code || "");
  return /timeout|5\d\d|unavailable|econnreset|network|database_transient|rate_limited|concurrency_full|quota/.test(value);
}

function classifyAutomationError(error) {
  if (error instanceof AutomationError) {
    return { code: error.code, message: error.message, errorClass: error.errorClass, retryable: error.retryable, details: error.details || {} };
  }
  const message = error?.message || "Node failed";
  const code = (message.split(":")[0] || "unknown_error").replace(/[^a-z0-9_]/gi, "_").toLowerCase();
  const errorClass = classifyErrorCode(code || message);
  return { code: code || "unknown_error", message, errorClass, retryable: isRetryableErrorCode(code || message), details: {} };
}

function retryPolicyForNode(node) {
  const config = node.config || {};
  const maxAttempts = Math.min(AUTOMATION_LIMITS.maxNodeAttempts, Math.max(1, Number(config.retry_max_attempts || config.retry_count || (config.retry_policy === "default" ? 3 : 1)) || 1));
  return {
    maxAttempts,
    initialDelay: Math.max(1, Number(config.retry_initial_delay_seconds || config.retry_delay_seconds || 10) || 10),
    multiplier: Math.max(1, Number(config.retry_backoff_multiplier || 2) || 2),
    maxDelay: Math.min(AUTOMATION_SAFETY_DEFAULTS.maxRetryDelaySeconds, Math.max(1, Number(config.retry_max_delay_seconds || 300) || 300)),
    jitter: config.retry_jitter !== false
  };
}

function retryDelaySeconds(policy, attempt, runId, nodeId, scopeKey) {
  const base = Math.min(policy.maxDelay, Math.round(policy.initialDelay * Math.pow(policy.multiplier, Math.max(0, attempt - 1))));
  if (!policy.jitter) return base;
  const jitter = Math.round(base * 0.2 * hashNumber(`${runId}:${nodeId}:${scopeKey}:${attempt}:retry`));
  return Math.min(policy.maxDelay, base + jitter);
}

async function enforceRunBudget(run, node, scopeKey) {
  const company = (await ctx.pool.query(`SELECT automation_node_executions_per_minute FROM companies WHERE id = $1`, [run.company_id])).rows[0] || {};
  const version = (await ctx.pool.query(`SELECT settings FROM automation_versions WHERE id = $1`, [run.automation_version_id])).rows[0]?.settings || {};
  const maxNodes = Math.min(AUTOMATION_LIMITS.maxNodesPerRun, Number(version.max_node_executions || version.maxNodes || AUTOMATION_LIMITS.maxNodesPerRun));
  if (Number(run.current_node_count || 0) >= maxNodes) throw new AutomationError("budget_exceeded", "Run node execution budget exceeded", { retryable: false });
  const recentNodes = (await ctx.pool.query(`SELECT COUNT(*)::int AS count FROM automation_run_nodes rn JOIN automation_runs r ON r.id = rn.run_id WHERE r.company_id = $1 AND rn.created_at > now() - interval '1 minute'`, [run.company_id])).rows[0]?.count || 0;
  if (Number(recentNodes) >= Number(company.automation_node_executions_per_minute || AUTOMATION_SAFETY_DEFAULTS.nodeExecutionsPerMinute)) throw new AutomationError("rate_limited", "Company node execution quota reached", { retryable: true });
  if (node.node_type === "action") await enforceActionBudget(run, node, scopeKey, version);
}

async function enforceActionBudget(run, node, scopeKey, versionSettings = {}) {
  const key = node.config?.action_key || "";
  const counters = {
    customer: ["sms.send", "sms.send_mms", "payment.send_payment_sms", "service_plan.send_scheduling_sms", "call.send_followup_sms", "voicemail.send_followup_sms"],
    internal: ["internal.send_message", "internal.send_dm", "internal.send_group_message", "internal.send_channel_message", "employee.send_internal_message", "employee.send_push", "notification.send_push"],
    webhook: ["webhook.send"],
    child: ["automation.start"]
  };
  const field = counters.customer.includes(key) ? "customer_message_count" : counters.internal.includes(key) ? "internal_message_count" : counters.webhook.includes(key) ? "webhook_action_count" : counters.child.includes(key) ? "child_run_count" : null;
  if (!field) return;
  const limit = field === "customer_message_count" ? Number(versionSettings.max_customer_messages_per_run || AUTOMATION_SAFETY_DEFAULTS.maxCustomerMessagesPerRun)
    : field === "internal_message_count" ? Number(versionSettings.max_internal_messages_per_run || AUTOMATION_SAFETY_DEFAULTS.maxInternalMessagesPerRun)
    : field === "webhook_action_count" ? Number(versionSettings.max_webhook_actions_per_run || AUTOMATION_SAFETY_DEFAULTS.maxWebhookActionsPerRun)
    : Number(versionSettings.max_child_runs_per_run || AUTOMATION_SAFETY_DEFAULTS.maxChildRunsPerRun);
  const result = await ctx.pool.query(
    `UPDATE automation_runs SET ${field} = ${field} + 1, updated_at = now()
      WHERE id = $1 AND ${field} < $2
      RETURNING ${field}`,
    [run.id, limit]
  );
  if (!result.rowCount) throw new AutomationError("budget_exceeded", `Run ${field.replace(/_/g, " ")} budget exceeded`, { retryable: false, details: { action_key: key, scope_key: scopeKey } });
}

async function logRun(run, node, level, event, message, metadata = {}) {
  try {
    await ctx.pool.query(
      `INSERT INTO automation_logs(company_id, automation_id, run_id, node_id, level, event, message, metadata)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
      [run.company_id, run.automation_id, run.id, node?.id || null, level, event, message, JSON.stringify(redact(metadata))]
    );
  } catch (e) {
    console.error("[automations] log failed", e?.message || e);
  }
}

async function createDeadLetter({ companyId, sourceType, sourceId = null, automationId = null, runId = null, eventType = null, subjectType = null, subjectId = null, attempts = 0, errorCode = null, errorMessage = null, metadata = {} }) {
  await ctx.pool.query(
    `INSERT INTO automation_dead_letters(company_id, source_type, source_id, automation_id, run_id, event_type, subject_type, subject_id, attempts, error_code, error_message, metadata)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
    [companyId, sourceType, sourceId, automationId, runId, eventType, subjectType, subjectId ? String(subjectId) : null, attempts, errorCode, (errorMessage || "").slice(0, 1000), JSON.stringify(redact(metadata))]
  );
}

async function getConfirmedActionEffect(runId, nodeId, scopeKey, effectType) {
  return (await ctx.pool.query(
    `SELECT * FROM automation_action_effects WHERE run_id = $1 AND node_id = $2 AND scope_key = $3 AND effect_type = $4 AND status = 'confirmed' LIMIT 1`,
    [runId, nodeId, scopeKey, effectType]
  )).rows[0] || null;
}

async function recordActionEffect(runId, nodeId, scopeKey, effectType, status, result = {}, externalId = null) {
  const effectKey = `${effectType}:${runId}:${nodeId}:${scopeKey}`;
  await ctx.pool.query(
    `INSERT INTO automation_action_effects(run_id, node_id, scope_key, effect_key, effect_type, status, external_id, result)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
     ON CONFLICT(run_id, node_id, scope_key, effect_key)
     DO UPDATE SET status = EXCLUDED.status, external_id = COALESCE(EXCLUDED.external_id, automation_action_effects.external_id), result = EXCLUDED.result, updated_at = now()`,
    [runId, nodeId, scopeKey, effectKey, effectType, status, externalId, JSON.stringify(redact(result || {}))]
  );
}

async function retryDeadLetter(id, companyId, userId) {
  const issue = (await ctx.pool.query(`SELECT * FROM automation_dead_letters WHERE id = $1 AND company_id = $2 AND status = 'open' FOR UPDATE`, [id, companyId])).rows[0];
  if (!issue) return null;
  if (issue.source_type === "event" && issue.source_id) {
    await ctx.pool.query(`UPDATE automation_events SET processing_status = 'pending', next_attempt_at = now(), locked_at = NULL, locked_by = NULL, error = NULL WHERE id = $1 AND company_id = $2`, [issue.source_id, companyId]);
  }
  if (issue.source_type === "scheduled_event" && issue.source_id) {
    await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'scheduled', next_attempt_at = now(), error = NULL, updated_at = now() WHERE id = $1 AND company_id = $2`, [issue.source_id, companyId]);
  }
  await ctx.pool.query(`UPDATE automation_dead_letters SET status = 'retried', dismissed_at = now(), metadata = metadata || $3::jsonb WHERE id = $1 AND company_id = $2`, [id, companyId, JSON.stringify({ retried_by_user_id: userId, retried_at: new Date().toISOString() })]);
  return { ok: true, source_type: issue.source_type, source_id: issue.source_id };
}

async function automationHealth(companyId) {
  const scalar = async (sql, params = [companyId]) => Number((await ctx.pool.query(sql, params)).rows[0]?.count || 0);
  const settings = (await ctx.pool.query(
    `SELECT automations_enabled, automation_emergency_stopped_at, automated_customer_messages_enabled FROM companies WHERE id = $1`,
    [companyId]
  )).rows[0] || {};
  return {
    settings,
    active_automations: await scalar(`SELECT COUNT(*)::int AS count FROM automation_definitions WHERE company_id = $1 AND status = 'published'`),
    paused_automations: await scalar(`SELECT COUNT(*)::int AS count FROM automation_definitions WHERE company_id = $1 AND status = 'paused'`),
    runs_today: await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE company_id = $1 AND created_at >= CURRENT_DATE`),
    failed_runs_today: await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE company_id = $1 AND status = 'failed' AND created_at >= CURRENT_DATE`),
    waiting_runs: await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE company_id = $1 AND status = 'waiting'`),
    queued_events: await scalar(`SELECT COUNT(*)::int AS count FROM automation_events WHERE company_id = $1 AND processing_status IN ('pending','failed')`),
    dead_letter_events: await scalar(`SELECT COUNT(*)::int AS count FROM automation_dead_letters WHERE company_id = $1 AND status = 'open'`),
    oldest_queued_event_at: (await ctx.pool.query(`SELECT MIN(created_at) AS at FROM automation_events WHERE company_id = $1 AND processing_status IN ('pending','failed')`, [companyId])).rows[0]?.at || null
  };
}

async function retryAutomationRun(runId, companyId, userId) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1 AND company_id = $2 AND status IN ('failed','stopped','canceled')`, [runId, companyId])).rows[0];
  if (!run) return null;
  const recovery = await createRun({
    companyId,
    automationId: run.automation_id,
    versionId: run.automation_version_id,
    triggerEventId: run.trigger_event_id,
    subjectType: run.subject_type,
    subjectId: run.subject_id,
    manualUserId: userId,
    dryRun: !!run.dry_run,
    rootRunId: run.root_run_id || run.id,
    reentryKey: `${run.reentry_key || normalReentryKey(run.subject_type, run.subject_id, run.trigger_event_id)}:recovery:${randomUUID()}`,
    recoveredFromRunId: run.id
  });
  await cloneRecoveryState(run.id, recovery.id, "root");
  await installRunMonitors(recovery);
  setImmediate(() => runAutomation(recovery.id).catch((e) => console.error("[automations] recovery run failed", e?.message || e)));
  await logRun(recovery, null, "info", "run.recovery_started", "Recovery run started from beginning", { recovered_from_run_id: run.id });
  return recovery;
}

async function retryAutomationRunNode(runId, runNodeId, companyId, userId) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1 AND company_id = $2 AND status IN ('failed','stopped')`, [runId, companyId])).rows[0];
  const failedNode = (await ctx.pool.query(`SELECT * FROM automation_run_nodes WHERE id = $1 AND run_id = $2 AND status = 'failed'`, [runNodeId, runId])).rows[0];
  if (!run || !failedNode?.node_id) return null;
  const recovery = await createRun({
    companyId,
    automationId: run.automation_id,
    versionId: run.automation_version_id,
    triggerEventId: run.trigger_event_id,
    subjectType: run.subject_type,
    subjectId: run.subject_id,
    manualUserId: userId,
    dryRun: !!run.dry_run,
    rootRunId: run.root_run_id || run.id,
    reentryKey: `${run.reentry_key || normalReentryKey(run.subject_type, run.subject_id, run.trigger_event_id)}:node_recovery:${failedNode.id}`,
    recoveredFromRunId: run.id,
    recoveredFromRunNodeId: failedNode.id,
    recoveryStartNodeId: failedNode.node_id,
    recoveryScopeKey: failedNode.scope_key || "root"
  });
  await cloneRecoveryState(run.id, recovery.id, failedNode.scope_key || "root");
  await installRunMonitors(recovery);
  setImmediate(() => executeFromNode(recovery.id, failedNode.node_id, failedNode.scope_key || "root").catch((e) => console.error("[automations] recovery node failed", e?.message || e)));
  await logRun(recovery, null, "info", "run.node_recovery_started", "Recovery run started from failed node", { recovered_from_run_id: run.id, recovered_from_run_node_id: failedNode.id });
  return recovery;
}

async function retryAutomationIteration(runId, iterationId, companyId, userId) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1 AND company_id = $2`, [runId, companyId])).rows[0];
  const iteration = (await ctx.pool.query(`SELECT * FROM automation_run_iterations WHERE id = $1 AND run_id = $2 AND status = 'failed'`, [iterationId, runId])).rows[0];
  if (!run || !iteration) return null;
  const node = (await ctx.pool.query(`SELECT * FROM automation_nodes WHERE id = $1`, [iteration.foreach_node_id])).rows[0];
  if (!node) return null;
  const recovery = await createRun({
    companyId,
    automationId: run.automation_id,
    versionId: run.automation_version_id,
    triggerEventId: run.trigger_event_id,
    subjectType: run.subject_type,
    subjectId: run.subject_id,
    manualUserId: userId,
    dryRun: !!run.dry_run,
    rootRunId: run.root_run_id || run.id,
    reentryKey: `${run.reentry_key || normalReentryKey(run.subject_type, run.subject_id, run.trigger_event_id)}:iteration_recovery:${iteration.id}`,
    recoveredFromRunId: run.id,
    recoveryStartNodeId: node.id,
    recoveryScopeKey: iteration.scope_key
  });
  const cloned = (await ctx.pool.query(
    `INSERT INTO automation_run_iterations(run_id, foreach_node_id, foreach_node_key, parent_scope_key, scope_key, iteration_key, item_index, item_count, item_data, status, retry_of_iteration_id, attempt_number)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'queued',$10,$11) RETURNING *`,
    [recovery.id, iteration.foreach_node_id, iteration.foreach_node_key, iteration.parent_scope_key, iteration.scope_key, iteration.iteration_key, iteration.item_index, iteration.item_count, JSON.stringify(iteration.item_data || {}), iteration.id, Number(iteration.attempt_number || 1) + 1]
  )).rows[0];
  await cloneRecoveryState(run.id, recovery.id, iteration.scope_key);
  setImmediate(async () => {
    const graph = await loadGraph(recovery.automation_version_id, recovery.company_id);
    await traverse(recovery, graph, node, "item", cloned.scope_key);
  });
  return recovery;
}

async function cloneRecoveryState(fromRunId, toRunId, scopeKey) {
  await ctx.pool.query(
    `INSERT INTO automation_variables(run_id, name, value)
     SELECT $2, name, value FROM automation_variables WHERE run_id = $1
     ON CONFLICT(run_id, name) DO NOTHING`,
    [fromRunId, toRunId]
  );
  const rows = (await ctx.pool.query(
    `SELECT node_key, output_snapshot, scope_key FROM automation_run_nodes
      WHERE run_id = $1 AND status = 'completed' AND scope_key IN ('root', $2)
      ORDER BY created_at ASC`,
    [fromRunId, scopeKey || "root"]
  )).rows;
  for (const row of rows) {
    await ctx.pool.query(
      `INSERT INTO automation_run_nodes(run_id, node_id, node_key, status, scope_key, attempt_number, output_snapshot, started_at, completed_at)
       VALUES($1,NULL,$2,'completed',$3,1,$4::jsonb,now(),now())`,
      [toRunId, row.node_key, row.scope_key || "root", JSON.stringify(row.output_snapshot || {})]
    );
  }
}

async function maybeAutoPauseAutomation(run, code, message) {
  const def = (await ctx.pool.query(`SELECT * FROM automation_definitions WHERE id = $1`, [run.automation_id])).rows[0];
  if (!def?.failure_auto_pause_enabled) return;
  const threshold = Number(def.failure_auto_pause_threshold || 10);
  const windowSeconds = Number(def.failure_auto_pause_window_seconds || 3600);
  const recent = (await ctx.pool.query(
    `SELECT COUNT(*)::int AS count FROM automation_runs
      WHERE automation_id = $1 AND status = 'failed' AND updated_at > now() - ($2::int * interval '1 second')`,
    [run.automation_id, windowSeconds]
  )).rows[0]?.count || 0;
  if (Number(recent) + 1 < threshold) return;
  await ctx.pool.query(`UPDATE automation_definitions SET status = 'paused', updated_at = now(), metadata = metadata || $2::jsonb WHERE id = $1 AND status = 'published'`, [run.automation_id, JSON.stringify({ auto_paused_reason: code, auto_paused_message: message, auto_paused_at: new Date().toISOString() })]);
  await logRun(run, null, "warn", "automation.auto_paused", "Automation auto-paused after repeated failures", { code, message });
}

async function loadRunDetail(runId, companyId) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1 AND company_id = $2`, [runId, companyId])).rows[0];
  if (!run) return null;
  const nodes = (await ctx.pool.query(`SELECT * FROM automation_run_nodes WHERE run_id = $1 ORDER BY created_at ASC`, [runId])).rows;
  const logs = (await ctx.pool.query(`SELECT * FROM automation_logs WHERE run_id = $1 ORDER BY created_at ASC`, [runId])).rows;
  const waits = (await ctx.pool.query(`SELECT * FROM automation_waits WHERE run_id = $1 ORDER BY created_at ASC`, [runId])).rows;
  const iterations = (await ctx.pool.query(`SELECT * FROM automation_run_iterations WHERE run_id = $1 ORDER BY created_at ASC, item_index ASC`, [runId])).rows;
  const merges = (await ctx.pool.query(`SELECT * FROM automation_merge_arrivals WHERE run_id = $1 ORDER BY arrived_at ASC`, [runId])).rows;
  const goals = (await ctx.pool.query(`SELECT * FROM automation_run_goals WHERE run_id = $1 ORDER BY reached_at ASC`, [runId])).rows;
  return { run, nodes, logs, waits, iterations, merges, goals };
}

function safeJson(value) {
  return JSON.parse(JSON.stringify(value || {}));
}

function safeAutomationErrorResponse(error, fallbackCode, fallbackMessage) {
  const message = String(error?.message || "");
  let code = fallbackCode;
  if (error?.code === "23505" || /duplicate key|unique/i.test(message)) code = "version_number_conflict";
  if (/stage_not_found/i.test(message)) code = "missing_stage";
  if (/contact_not_found/i.test(message)) code = "missing_contact";
  if (/validation/i.test(message)) code = "validation_failed";
  const friendly = {
    version_number_conflict: "WolfCRM couldn't create a unique published automation version.",
    missing_stage: "The selected Pipeline Stage no longer exists.",
    missing_contact: "The selected Contact no longer exists.",
    validation_failed: "Fix the highlighted automation settings before publishing."
  };
  return {
    error: fallbackCode,
    code,
    message: friendly[code] || fallbackMessage
  };
}

function safeSnapshot(context) {
  return {
    event: context.event ? { type: context.event.type, subject_type: context.event.subject_type, subject_id: context.event.subject_id } : null,
    subject: context.subject || null,
    scope: context.scope || null,
    iteration: context.iteration || null,
    variables: context.variables || {}
  };
}

function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = /secret|token|password|authorization|cookie|key/i.test(k) ? "[redacted]" : redact(v);
    return out;
  }
  return value;
}

export const automationTestHooks = {
  actionCatalog: () => actionCatalog,
  actionExecutors: () => actionExecutors,
  bootstrapAutomationSchema,
  cancelAutomationRun,
  ensureDraftVersion,
  loadRunDetail,
  loadVersionGraph,
  processAutomationEvents,
  processDueWaits,
  processScheduledAutomationEvents,
  publishAutomation,
  runAutomation,
  saveDraftGraph,
  startDraftTestRun,
  startManualRun,
  triggerCatalog: () => triggerCatalog,
  validateGraphPayload
};
