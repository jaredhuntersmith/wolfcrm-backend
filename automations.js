import { randomUUID } from "crypto";
import net from "net";

const AUTOMATION_LIMITS = {
  maxNodesPerRun: 5000,
  maxNodeAttempts: 8,
  maxChildDepth: 12,
  maxRuntimeHours: 24 * 30,
  eventBatchSize: 25,
  waitBatchSize: 25
};

let ctx = null;

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
  ["payment.succeeded", "Payment Succeeded", "Payments", "A Stripe payment succeeded.", ["payment", "contact"], ["payment.succeeded"]],
  ["payment.failed", "Payment Failed", "Payments", "A Stripe payment failed.", ["payment", "contact"], ["payment.failed"]],
  ["service_plan.created", "Service Plan Created", "Service Plans", "A service plan was created.", ["service_plan"], ["service_plan.created"]],
  ["service_plan.serviced", "Service Plan Serviced", "Service Plans", "A service plan was marked serviced.", ["service_plan"], ["service_plan.serviced"]],
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
  ["pipeline.move_stage", "Move Pipeline Stage", "Pipeline", "Moves an existing contact opportunity to a stage.", ["contact", "opportunity"], ["default"]],
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
  ["sms.send", "Send SMS", "Phone", "Sends SMS through the configured company phone line.", ["contact", "sms_conversation"], ["default"]],
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
  if (key.startsWith("lead.")) return "person.badge.plus";
  if (key.includes("tag")) return "tag";
  if (key.startsWith("pipeline.won")) return "trophy";
  if (key.startsWith("pipeline.lost")) return "xmark.circle";
  if (key.startsWith("pipeline.")) return "arrow.right";
  if (key.startsWith("contact.")) return "person.crop.circle";
  return "bolt";
}

function actionIcon(key) {
  if (key.includes("tag")) return "tag";
  if (key.includes("delete") || key.includes("remove") || key.includes("lost")) return "xmark.circle";
  if (key.includes("won")) return "trophy";
  if (key.startsWith("pipeline.")) return "arrow.right";
  if (key.startsWith("contact.")) return "person.crop.circle.badge.checkmark";
  if (key.startsWith("sms.")) return "message";
  if (key.startsWith("notification.")) return "bell";
  return "bolt";
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
  installAutomationRoutes();
  startAutomationProcessors();
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
      reentry_mode TEXT NOT NULL DEFAULT 'after_previous_completion',
      cooldown_seconds INTEGER,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
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
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS automation_events_company_type_idx ON automation_events(company_id, event_type, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS automation_events_status_idx ON automation_events(processing_status, processed_at, created_at);
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
      root_run_id UUID REFERENCES automation_runs(id) ON DELETE SET NULL,
      manual_started_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      dry_run BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_runs_company_status_idx ON automation_runs(company_id, status, created_at DESC);
    CREATE INDEX IF NOT EXISTS automation_runs_automation_idx ON automation_runs(automation_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS automation_runs_subject_idx ON automation_runs(company_id, automation_id, subject_type, subject_id);

    CREATE TABLE IF NOT EXISTS automation_run_nodes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      node_id UUID REFERENCES automation_nodes(id) ON DELETE SET NULL,
      node_key TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      attempt_number INTEGER NOT NULL DEFAULT 1,
      input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
      output_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
      error_code TEXT,
      error_message TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_run_nodes_run_idx ON automation_run_nodes(run_id, created_at);
    CREATE INDEX IF NOT EXISTS automation_run_nodes_node_idx ON automation_run_nodes(run_id, node_key, attempt_number);

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
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS automation_waits_due_idx ON automation_waits(status, resume_at) WHERE status = 'waiting' AND resume_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS automation_waits_timeout_idx ON automation_waits(status, timeout_at) WHERE status = 'waiting' AND timeout_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS automation_waits_event_idx ON automation_waits(status, event_type) WHERE status = 'waiting' AND event_type IS NOT NULL;

    CREATE TABLE IF NOT EXISTS automation_variables (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id UUID NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      value JSONB NOT NULL DEFAULT 'null'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(run_id, name)
    );

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
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      fired_at TIMESTAMPTZ,
      UNIQUE(company_id, schedule_key)
    );
    CREATE INDEX IF NOT EXISTS automation_scheduled_events_due_idx ON automation_scheduled_events(status, scheduled_for);
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

    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automated_customer_messages_enabled BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_sms_default_business_hours_policy TEXT NOT NULL DEFAULT 'send_immediately';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_sms_max_per_contact_hour INTEGER NOT NULL DEFAULT 6;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS automation_sms_max_per_contact_day INTEGER NOT NULL DEFAULT 20;
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
        { key: "wait", display_name: "Wait", category: "Timing", description: "Persists a duration, date, or event wait.", outputs: ["default", "event", "timeout"], config_fields: [{ key: "mode", type: "select", options: ["duration", "until_datetime", "event_wait"] }] },
        { key: "variable.set", display_name: "Set Variable", category: "Utility", description: "Stores a run variable.", outputs: ["default"], config_fields: [{ key: "name", type: "text" }, { key: "value", type: "template" }] },
        { key: "automation.start", display_name: "Start Automation", category: "Utility", description: "Starts another published automation.", outputs: ["default"], config_fields: [{ key: "automation_id", type: "automation" }] },
        { key: "note", display_name: "Note", category: "Notes", description: "Editor-only annotation. Does not execute.", outputs: [], config_fields: [{ key: "title", type: "text" }, { key: "body", type: "multiline" }] }
      ]
    });
  });

  app.get("/api/automations/settings", authRequired, requireEmployer, async (req, res) => {
    try {
      const { rows } = await ctx.pool.query(
        `SELECT automated_customer_messages_enabled,
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
      const enabled = req.body?.automated_customer_messages_enabled !== false;
      const policy = ["send_immediately", "defer_until_business_hours", "skip_if_outside_business_hours"].includes(req.body?.automation_sms_default_business_hours_policy)
        ? req.body.automation_sms_default_business_hours_policy
        : "send_immediately";
      const hourMax = Math.max(0, Math.min(200, Number(req.body?.automation_sms_max_per_contact_hour ?? 6) || 0));
      const dayMax = Math.max(0, Math.min(1000, Number(req.body?.automation_sms_max_per_contact_day ?? 20) || 0));
      const { rows } = await ctx.pool.query(
        `UPDATE companies
            SET automated_customer_messages_enabled = $2,
                automation_sms_default_business_hours_policy = $3,
                automation_sms_max_per_contact_hour = $4,
                automation_sms_max_per_contact_day = $5
          WHERE id = $1
          RETURNING automated_customer_messages_enabled,
                    automation_sms_default_business_hours_policy,
                    automation_sms_max_per_contact_hour,
                    automation_sms_max_per_contact_day`,
        [req.companyId, enabled, policy, hourMax, dayMax]
      );
      res.json(rows[0] || {});
    } catch (e) {
      console.error("[automations] settings update failed", e?.message || e);
      res.status(500).json({ error: "automation_settings_update_failed" });
    }
  });

  app.post("/api/automations/pause-all", authRequired, requireEmployer, async (req, res) => {
    try {
      await ctx.pool.query(`UPDATE automation_definitions SET status = 'paused', updated_at = now() WHERE company_id = $1 AND status = 'published'`, [req.companyId]);
      res.json({ ok: true });
    } catch (e) {
      console.error("[automations] pause all failed", e?.message || e);
      res.status(500).json({ error: "automation_pause_all_failed" });
    }
  });

  app.post("/api/automations/resume-all", authRequired, requireEmployer, async (req, res) => {
    try {
      await ctx.pool.query(`UPDATE automation_definitions SET status = 'published', pause_until = NULL, updated_at = now() WHERE company_id = $1 AND status = 'paused'`, [req.companyId]);
      res.json({ ok: true });
    } catch (e) {
      console.error("[automations] resume all failed", e?.message || e);
      res.status(500).json({ error: "automation_resume_all_failed" });
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
    const allowed = ["name", "description", "folder_id", "allow_manual_trigger", "max_parallel_runs_per_subject", "reentry_mode", "cooldown_seconds", "metadata"];
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
      res.status(500).json({ error: "automation_publish_failed" });
    }
  });

  app.post("/api/automations/validate-graph", authRequired, requireEmployer, async (req, res) => {
    res.json(validateGraphPayload(req.body || {}));
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
      const { rows } = await ctx.pool.query(
        `UPDATE automation_runs SET status = 'canceled', completed_at = now(), updated_at = now()
          WHERE id = $1 AND company_id = $2 AND status IN ('queued','running','waiting','paused')
          RETURNING *`,
        [req.params.runId, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "not_found" });
      await ctx.pool.query(`UPDATE automation_waits SET status = 'canceled', updated_at = now() WHERE run_id = $1 AND status = 'waiting'`, [req.params.runId]);
      await logRun(rows[0], null, "info", "run.canceled", "Run canceled by employer", { user_id: req.userId });
      res.json(rows[0]);
    } catch (e) {
      res.status(500).json({ error: "automation_cancel_failed" });
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
  const validTypes = new Set(["trigger", "action", "condition", "wait", "branch", "sub_automation", "utility", "note"]);
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
      if (["sms.delete_local_message"].includes(config.action_key) && !config.message_id) warnings.push(`message_id_defaults_to_context:${nodeKey}`);
      if (["sms.mark_conversation_read", "sms.mark_conversation_unread", "sms.delete_local_conversation"].includes(config.action_key) && !config.conversation_id) warnings.push(`conversation_id_defaults_to_context:${nodeKey}`);
      if (config.action_key === "internal.send_dm" && !config.recipient_user_id) errors.push(`internal_recipient_required:${nodeKey}`);
      if (config.action_key === "internal.send_channel_message" && !config.channel_id) errors.push(`internal_channel_required:${nodeKey}`);
      if (config.action_key === "internal.create_channel" && !config.name) errors.push(`internal_channel_name_required:${nodeKey}`);
      if (["call.set_disposition"].includes(config.action_key) && !config.disposition) errors.push(`call_disposition_required:${nodeKey}`);
    }
    if (nodeType === "trigger" && config.trigger_key === "job.relative_time" && (!config.reference || !config.direction || !config.amount || !config.unit)) errors.push(`relative_time_trigger_incomplete:${nodeKey}`);
    if (nodeType === "trigger" && ["sms.no_reply", "sms.conversation_inactive", "voicemail.unread_for"].includes(config.trigger_key) && Number(config.amount || 0) <= 0) errors.push(`communication_duration_required:${nodeKey}`);
    if (nodeType === "trigger" && config.trigger_key === "sms.keyword_received" && !(Array.isArray(config.keywords) && config.keywords.length)) errors.push(`sms_keywords_required:${nodeKey}`);
    if (nodeType === "trigger" && ["call.short_call", "call.long_call"].includes(config.trigger_key) && Number(config.threshold_seconds || 0) <= 0) errors.push(`call_duration_threshold_required:${nodeKey}`);
  }
  for (const edge of edges) {
    if (!nodeIds.has(edge.source_node_id || edge.sourceNodeId)) errors.push(`edge_source_missing:${edge.id || ""}`);
    if (!nodeIds.has(edge.target_node_id || edge.targetNodeId)) errors.push(`edge_target_missing:${edge.id || ""}`);
  }
  if (!nodes.some((n) => (n.node_type || n.nodeType) === "trigger")) errors.push("trigger_required");
  if (detectCycle(nodes, edges)) warnings.push("cycle_detected_execution_safety_limits_apply");
  return { valid: errors.length === 0, errors, warnings };
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
  const draft = await ensureDraftVersion(automationId, companyId, userId);
  if (!draft) return null;
  const graph = await loadVersionGraph(draft.id, companyId);
  const validation = validateGraphPayload({ nodes: graph.nodes, edges: graph.edges, settings: graph.settings });
  if (!validation.valid) return validation;
  const db = await ctx.pool.connect();
  try {
    await db.query("BEGIN");
    const maxRow = (await db.query(`SELECT COALESCE(MAX(version_number),0)::int AS n FROM automation_versions WHERE automation_id = $1 AND status = 'published'`, [automationId])).rows[0];
    const published = (await db.query(
      `INSERT INTO automation_versions(automation_id, company_id, version_number, status, settings, created_by_user_id, published_at)
       SELECT automation_id, company_id, $3, 'published', settings, $4, now()
         FROM automation_versions WHERE id = $1 AND company_id = $2
       RETURNING *`,
      [draft.id, companyId, maxRow.n + 1, userId]
    )).rows[0];
    await copyGraph(db, draft.id, published.id, companyId);
    await db.query(`UPDATE automation_versions SET status = 'retired', updated_at = now() WHERE automation_id = $1 AND company_id = $2 AND status = 'published' AND id <> $3`, [automationId, companyId, published.id]);
    const newDraft = (await db.query(
      `INSERT INTO automation_versions(automation_id, company_id, version_number, status, settings, created_by_user_id)
       VALUES($1,$2,$3,'draft',$4::jsonb,$5) RETURNING *`,
      [automationId, companyId, published.version_number + 1, JSON.stringify(published.settings || {}), userId]
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

async function processAutomationEvents() {
  if (!ctx?.pool) return;
  const db = await ctx.pool.connect();
  let events = [];
  try {
    await db.query("BEGIN");
    events = (await db.query(
      `SELECT * FROM automation_events
        WHERE processing_status IN ('pending','failed')
          AND processed_at IS NULL
        ORDER BY occurred_at ASC, created_at ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED`,
      [AUTOMATION_LIMITS.eventBatchSize]
    )).rows;
    await db.query(`UPDATE automation_events SET processing_status = 'processing' WHERE id = ANY($1::uuid[])`, [events.map((e) => e.id)]);
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
      await wakeEventWaits(event);
      await startRunsForEvent(event);
      await ctx.pool.query(`UPDATE automation_events SET processing_status = 'processed', processed_at = now(), error = NULL WHERE id = $1`, [event.id]);
    } catch (e) {
      console.error("[automations] event processing failed", { id: event.id, eventType: event.event_type, message: e?.message });
      await ctx.pool.query(`UPDATE automation_events SET processing_status = 'failed', error = $2 WHERE id = $1`, [event.id, (e?.message || "event_failed").slice(0, 1000)]);
    }
  }
}

async function startRunsForEvent(event) {
  const { rows } = await ctx.pool.query(
    `SELECT DISTINCT d.*, v.id AS version_id
       FROM automation_definitions d
       JOIN automation_versions v ON v.id = d.active_version_id AND v.status = 'published'
       JOIN automation_nodes n ON n.version_id = v.id AND n.node_type = 'trigger'
      WHERE d.company_id = $1
        AND d.status = 'published'
        AND (d.pause_until IS NULL OR d.pause_until <= now())
        AND (
          n.config->>'trigger_key' = $2
          OR (n.config->'event_types') ? $2
        )`,
    [event.company_id, event.event_type]
  );
  for (const automation of rows) {
    const triggers = (await ctx.pool.query(
      `SELECT * FROM automation_nodes WHERE version_id = $1 AND company_id = $2 AND node_type = 'trigger'`,
      [automation.version_id, event.company_id]
    )).rows;
    if (!triggers.some((node) => triggerMatchesEvent(node, event))) continue;
    if (!(await canStartRun(automation, event))) continue;
    const run = await createRun({
      companyId: event.company_id,
      automationId: automation.id,
      versionId: automation.version_id,
      triggerEventId: event.id,
      subjectType: event.subject_type,
      subjectId: event.subject_id,
      depth: 0,
      dryRun: false
    });
    await logRun(run, null, "info", "trigger.matched", `Trigger matched ${event.event_type}`, { event_id: event.id });
    await runAutomation(run.id);
  }
}

async function canStartRun(automation, event) {
  const mode = automation.reentry_mode || automation.metadata?.reentry_mode || "after_previous_completion";
  if (!event.subject_id || mode === "unlimited") return true;
  const baseParams = [automation.company_id, automation.id, event.subject_type, event.subject_id];
  if (mode === "once_ever_per_subject") {
    const existing = await ctx.pool.query(`SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND subject_type = $3 AND subject_id = $4 LIMIT 1`, baseParams);
    return !existing.rowCount;
  }
  if (mode === "once_while_active") {
    const active = await ctx.pool.query(`SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND subject_type = $3 AND subject_id = $4 AND status IN ('queued','running','waiting','paused') LIMIT 1`, baseParams);
    return !active.rowCount;
  }
  if (automation.cooldown_seconds) {
    const recent = await ctx.pool.query(
      `SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND subject_type = $3 AND subject_id = $4 AND created_at > now() - ($5::int * interval '1 second') LIMIT 1`,
      [...baseParams, automation.cooldown_seconds]
    );
    if (recent.rowCount) return false;
  }
  const active = await ctx.pool.query(`SELECT 1 FROM automation_runs WHERE company_id = $1 AND automation_id = $2 AND subject_type = $3 AND subject_id = $4 AND status IN ('queued','running','waiting','paused') LIMIT 1`, baseParams);
  return !active.rowCount;
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
    depth: 0
  });
  await logRun(run, null, "info", body.dry_run ? "run.dry_start" : "run.manual_start", "Manual run started", { subject_type: body.subject_type, subject_id: body.subject_id });
  setImmediate(() => runAutomation(run.id).catch((e) => console.error("[automations] manual run wake failed", e?.message || e)));
  return run;
}

async function createRun({ companyId, automationId, versionId, triggerEventId = null, subjectType = null, subjectId = null, manualUserId = null, dryRun = false, parentRunId = null, rootRunId = null, depth = 0 }) {
  const { rows } = await ctx.pool.query(
    `INSERT INTO automation_runs(company_id, automation_id, automation_version_id, trigger_event_id, subject_type, subject_id, status, started_at, manual_started_by_user_id, dry_run, parent_run_id, root_run_id, depth)
     VALUES($1,$2,$3,$4,$5,$6,'queued',now(),$7,$8,$9,$10,$11) RETURNING *`,
    [companyId, automationId, versionId, triggerEventId, subjectType, subjectId ? String(subjectId) : null, manualUserId, dryRun, parentRunId, rootRunId, depth]
  );
  if (!rootRunId) await ctx.pool.query(`UPDATE automation_runs SET root_run_id = id WHERE id = $1`, [rows[0].id]);
  return { ...rows[0], root_run_id: rows[0].root_run_id || rows[0].id };
}

async function runAutomation(runId, resumeFromNodeId = null, incomingPort = null) {
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
    await executeFromNode(run.id, node.id);
  }
  await completeRunIfIdle((await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [runId])).rows[0]);
}

async function executeFromNode(runId, nodeId) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [runId])).rows[0];
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  const graph = await loadGraph(run.automation_version_id, run.company_id);
  const node = graph.nodeById.get(nodeId);
  if (!node) return;
  if (node.node_type === "note") return;
  if (await shouldStopRun(run)) return stopRun(run, "stop_condition", "Global stop condition matched");
  const previous = await ctx.pool.query(
    `SELECT COUNT(*)::int AS count FROM automation_run_nodes WHERE run_id = $1 AND node_key = $2 AND status = 'completed'`,
    [runId, node.node_key]
  );
  if (Number(previous.rows[0].count) > 0 && !node.config?.repeatable) {
    await traverse(run, graph, node, "default");
    return;
  }
  const attempt = Number(previous.rows[0].count) + 1;
  if (attempt > AUTOMATION_LIMITS.maxNodeAttempts) return failRun(run, "node_attempt_limit", `Node ${node.node_key} exceeded attempt limit`);
  const runNode = await beginRunNode(run, node, attempt);
  try {
    const result = await executeNode(run, node, runNode);
    if (result?.waiting) return;
    await finishRunNode(runNode.id, "completed", result?.output || {});
    await ctx.pool.query(`UPDATE automation_runs SET current_node_count = current_node_count + 1, updated_at = now() WHERE id = $1`, [run.id]);
    await traverse(run, graph, node, result?.port || "default");
  } catch (e) {
    const retryCount = Number(node.config?.retry_count || 0);
    await finishRunNode(runNode.id, "failed", {}, "node_failed", e?.message || "Node failed");
    await logRun(run, node, "error", "node.failed", `Node ${node.title || node.node_key} failed`, { error: e?.message });
    if (attempt <= retryCount && isRetrySafe(node)) {
      const delay = Math.max(1, Number(node.config?.retry_delay_seconds || 10));
      await createWait(run, node, "duration", { resume_at: new Date(Date.now() + delay * 1000).toISOString(), resume_node_id: node.id, retry: true });
      return;
    }
    if (node.config?.continue_on_error) {
      await traverse(run, graph, node, "error");
      return;
    }
    await failRun(run, "node_failed", e?.message || "Node failed");
  }
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

async function beginRunNode(run, node, attempt) {
  const context = await buildRunContext(run, { slim: true });
  const { rows } = await ctx.pool.query(
    `INSERT INTO automation_run_nodes(run_id, node_id, node_key, status, attempt_number, input_snapshot, started_at)
     VALUES($1,$2,$3,'running',$4,$5::jsonb,now()) RETURNING *`,
    [run.id, node.id, node.node_key, attempt, JSON.stringify(safeSnapshot(context))]
  );
  await logRun(run, node, "info", "node.started", `Started ${node.title || node.node_key}`, {});
  return rows[0];
}

async function finishRunNode(id, status, output, errorCode = null, errorMessage = null) {
  await ctx.pool.query(
    `UPDATE automation_run_nodes SET status = $2, output_snapshot = $3::jsonb, error_code = $4, error_message = $5, completed_at = now(), updated_at = now()
      WHERE id = $1`,
    [id, status, JSON.stringify(safeJson(output || {})), errorCode, errorMessage]
  );
}

async function executeNode(run, node, runNode) {
  if (node.node_type === "trigger") {
    await logRun(run, node, "info", "trigger.started", "Trigger node entered", {});
    return { port: "default", output: { triggered: true } };
  }
  if (node.node_type === "condition") {
    const context = await buildRunContext(run);
    const result = evaluateCondition(node.config?.condition || node.config, context);
    await logRun(run, node, "info", result ? "condition.true" : "condition.false", `Condition evaluated ${result ? "true" : "false"}`, {});
    return { port: result ? "true" : "false", output: { result } };
  }
  if (node.node_type === "branch") {
    const context = await buildRunContext(run);
    const value = resolveTemplate(node.config?.input || "", context).trim();
    const branches = Array.isArray(node.config?.branches) ? node.config.branches.map(String) : [];
    const port = branches.includes(value) ? value : "default";
    await logRun(run, node, "info", "branch.selected", `Branch selected ${port}`, { value });
    return { port, output: { value, port } };
  }
  if (node.node_type === "wait") {
    const wait = await createWaitForNode(run, node);
    await ctx.pool.query(`UPDATE automation_run_nodes SET status = 'waiting', output_snapshot = $2::jsonb, updated_at = now() WHERE id = $1`, [runNode.id, JSON.stringify({ wait_id: wait.id })]);
    await ctx.pool.query(`UPDATE automation_runs SET status = 'waiting', updated_at = now() WHERE id = $1`, [run.id]);
    await logRun(run, node, "info", "wait.created", "Wait created", { wait_id: wait.id, wait_type: wait.wait_type, resume_at: wait.resume_at, event_type: wait.event_type, timeout_at: wait.timeout_at });
    return { waiting: true };
  }
  if (node.node_type === "utility" && (node.config?.utility_key === "variable.set" || node.config?.action_key === "variable.set")) {
    const context = await buildRunContext(run);
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
  if (node.node_type === "sub_automation") {
    return executeAutomationStart(run, node, node.config || {});
  }
  if (node.node_type === "action") {
    const actionKey = node.config?.action_key;
    const executor = actionExecutors[actionKey];
    if (!executor) throw new Error(`unknown_action:${actionKey}`);
    if (run.dry_run) {
      const context = await buildRunContext(run);
      const resolved = resolveConfig(node.config || {}, context);
      await logRun(run, node, "info", "action.dry_run", `Would execute ${actionKey}`, { resolved_config: redact(resolved) });
      return { port: "default", output: { would_execute: actionKey, resolved_config: redact(resolved) } };
    }
    await logRun(run, node, "info", "action.started", `Action started ${actionKey}`, {});
    const output = await executor(run, node, node.config || {});
    if (output?.waiting) {
      await ctx.pool.query(`UPDATE automation_run_nodes SET status = 'waiting', output_snapshot = $2::jsonb, updated_at = now() WHERE id = $1`, [runNode.id, JSON.stringify(output)]);
      return output;
    }
    await logRun(run, node, "info", "action.completed", `Action completed ${actionKey}`, {});
    return { port: "default", output };
  }
  return { port: "default", output: {} };
}

async function traverse(run, graph, node, port) {
  const edges = (graph.edgesBySource[node.id] || []).filter((edge) => portMatches(edge.source_port, port)).sort(edgeSort);
  if (!edges.length) return;
  for (const edge of edges) {
    await executeFromNode(run.id, edge.target_node_id);
  }
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
}

async function stopRun(run, code, message) {
  await ctx.pool.query(
    `UPDATE automation_runs SET status = 'stopped', completed_at = COALESCE(completed_at, now()), error_code = $2, error_message = $3, updated_at = now()
      WHERE id = $1`,
    [run.id, code, message]
  );
  await logRun(run, null, "info", "run.stopped", message, { code });
}

async function shouldStopRun(run) {
  const version = (await ctx.pool.query(`SELECT settings FROM automation_versions WHERE id = $1`, [run.automation_version_id])).rows[0];
  const stop = version?.settings?.stop_condition;
  if (!stop) return false;
  const context = await buildRunContext(run);
  return evaluateCondition(stop, context);
}

async function createWaitForNode(run, node) {
  const context = await buildRunContext(run);
  const mode = node.config?.mode || node.config?.wait_type || "duration";
  if (mode === "duration") {
    const resumeAt = new Date(Date.now() + parseDurationMs(resolveTemplate(node.config?.duration || node.config?.value || "1 minute", context)));
    return createWait(run, node, "duration", { resume_at: resumeAt.toISOString() });
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
    return createWait(run, node, "until_datetime", { resume_at: date.toISOString() });
  }
  if (mode === "event_wait") {
    const timeoutMs = node.config?.timeout ? parseDurationMs(resolveTemplate(node.config.timeout, context)) : null;
    return createWait(run, node, "event", {
      event_type: node.config?.event_type,
      event_filter: node.config?.event_filter || null,
      timeout_at: timeoutMs ? new Date(Date.now() + timeoutMs).toISOString() : null
    });
  }
  throw new Error("unknown_wait_mode");
}

async function createWait(run, node, waitType, values) {
  const { rows } = await ctx.pool.query(
    `INSERT INTO automation_waits(run_id, node_id, wait_type, resume_at, event_type, event_filter, timeout_at, status)
     VALUES($1,$2,$3,$4::timestamptz,$5,$6::jsonb,$7::timestamptz,'waiting') RETURNING *`,
    [run.id, node.id, waitType, values.resume_at || null, values.event_type || null, values.event_filter ? JSON.stringify(values.event_filter) : null, values.timeout_at || null]
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
    `UPDATE automation_waits w
        SET status = 'ready', updated_at = now()
       FROM automation_runs r
      WHERE w.run_id = r.id
        AND w.status = 'waiting'
        AND w.wait_type = 'event'
        AND w.event_type = $1
        AND r.company_id = $2
        AND (
          w.event_filter IS NULL
          OR COALESCE(w.event_filter->>'subject_id','') = ''
          OR w.event_filter->>'subject_id' = $3
          OR (w.event_filter->>'same_subject')::boolean = true AND r.subject_type = $4 AND r.subject_id = $3
        )
      RETURNING w.*`,
    [event.event_type, event.company_id, event.subject_id || "", event.subject_type || ""]
  );
  for (const wait of rows) await resumeWait(wait, "event");
}

async function resumeWait(wait, port) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1`, [wait.run_id])).rows[0];
  if (!run || ["completed", "failed", "canceled", "stopped"].includes(run.status)) return;
  await ctx.pool.query(`UPDATE automation_waits SET status = CASE WHEN $2 = 'timeout' THEN 'timed_out' ELSE 'completed' END, updated_at = now() WHERE id = $1`, [wait.id, port]);
  const node = (await ctx.pool.query(`SELECT * FROM automation_nodes WHERE id = $1`, [wait.node_id])).rows[0];
  if (node) await logRun(run, node, "info", "wait.resumed", `Wait resumed through ${port}`, { wait_id: wait.id });
  await runAutomation(run.id, wait.node_id, port);
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
          SET status = 'firing', updated_at = now()
        WHERE id IN (
          SELECT id FROM automation_scheduled_events
           WHERE status = 'scheduled' AND scheduled_for <= now()
           ORDER BY scheduled_for ASC
           LIMIT 50
           FOR UPDATE SKIP LOCKED
        )
        RETURNING *`
    )).rows;
    await db.query("COMMIT");
  } catch (e) {
    await db.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    db.release();
  }
  for (const row of rows) {
    if (!(await shouldFireScheduledAutomationEvent(row))) {
      await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'canceled', updated_at = now() WHERE id = $1`, [row.id]);
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
    await ctx.pool.query(`UPDATE automation_scheduled_events SET status = 'fired', fired_at = now(), updated_at = now() WHERE id = $1`, [row.id]);
    if (!eventId) console.warn("[automations] scheduled event emitted no id", { scheduleKey: row.schedule_key });
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
  return true;
}

async function buildRunContext(run, options = {}) {
  const event = run.trigger_event_id ? (await ctx.pool.query(`SELECT * FROM automation_events WHERE id = $1`, [run.trigger_event_id])).rows[0] : null;
  const company = (await ctx.pool.query(`SELECT id, name, website, address, phone, email, timezone, business_days, business_open_time, business_close_time FROM companies WHERE id = $1`, [run.company_id])).rows[0] || {};
  const now = new Date();
  const variables = Object.fromEntries((await ctx.pool.query(`SELECT name, value FROM automation_variables WHERE run_id = $1`, [run.id])).rows.map((r) => [r.name, r.value]));
  const nodeRows = options.slim ? [] : (await ctx.pool.query(`SELECT node_key, output_snapshot FROM automation_run_nodes WHERE run_id = $1 ORDER BY created_at ASC`, [run.id])).rows;
  const nodes = {};
  for (const row of nodeRows) nodes[row.node_key] = { output: row.output_snapshot || {} };
  const context = {
    company,
    event: event ? { id: event.id, type: event.event_type, payload: event.payload || {}, subject_type: event.subject_type, subject_id: event.subject_id } : {},
    variables,
    nodes,
    subject: { type: run.subject_type, id: run.subject_id },
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
  if (subjectType === "service_plan") return (await ctx.pool.query(`SELECT * FROM service_plans WHERE id::text = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "task") return loadTaskContext(companyId, subjectId);
  if (subjectType === "routine") return loadRoutineContext(companyId, subjectId);
  if (subjectType === "customer_reminder") return loadCustomerReminderContext(companyId, subjectId);
  if (subjectType === "payment") return (await ctx.pool.query(`SELECT * FROM payment_records WHERE id::text = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  return null;
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
  return type === "sms_conversation" || type === "sms_message" ? "sms" : type === "service_plan" ? "servicePlan" : type === "internal_message" || type === "internal_conversation" ? "internal" : type;
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
  return path.split(".").reduce((acc, key) => (acc == null ? undefined : acc[key]), root);
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
  return { pin_id: rows[0].id, contact_id: contactId };
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
  if (config.phone || config.to_phone || config.to_number) {
    return { contact_id: null, phone: resolveTemplate(config.phone || config.to_phone || config.to_number, context) };
  }
  const contactId = await resolveContactId(run, context, config);
  const contact = (await ctx.pool.query(`SELECT id, phone FROM contacts WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL`, [contactId, run.company_id])).rows[0];
  if (!contact) throw new Error("contact_not_found");
  return { contact_id: contact.id, phone: contact.phone };
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

async function executeWebhookSend(run, node, config) {
  const context = await buildRunContext(run);
  const method = (config.method || "POST").toString().toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) throw new Error("unsupported_method");
  const url = new URL(resolveTemplate(config.url || "", context));
  await assertSafeWebhookUrl(url);
  const headers = Object.fromEntries(Object.entries(resolveConfig(config.headers || {}, context)).filter(([k]) => !/authorization|cookie|token|secret/i.test(k)));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(15000, Math.max(1000, Number(config.timeout_ms || 8000))));
  try {
    const response = await fetch(url, {
      method,
      headers: { "content-type": "application/json", ...headers },
      body: ["GET", "DELETE"].includes(method) ? undefined : JSON.stringify(resolveConfig(config.body || {}, context)),
      signal: controller.signal
    });
    const text = (await response.text()).slice(0, 4096);
    if (!response.ok && !config.continue_on_http_error) throw new Error(`webhook_http_${response.status}`);
    return { status: response.status, body: text, headers: safeResponseHeaders(response.headers) };
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
  return ["notification.send_push", "sms.send", "webhook.send"].includes(node.config?.action_key);
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

async function loadRunDetail(runId, companyId) {
  const run = (await ctx.pool.query(`SELECT * FROM automation_runs WHERE id = $1 AND company_id = $2`, [runId, companyId])).rows[0];
  if (!run) return null;
  const nodes = (await ctx.pool.query(`SELECT * FROM automation_run_nodes WHERE run_id = $1 ORDER BY created_at ASC`, [runId])).rows;
  const logs = (await ctx.pool.query(`SELECT * FROM automation_logs WHERE run_id = $1 ORDER BY created_at ASC`, [runId])).rows;
  const waits = (await ctx.pool.query(`SELECT * FROM automation_waits WHERE run_id = $1 ORDER BY created_at ASC`, [runId])).rows;
  return { run, nodes, logs, waits };
}

function safeJson(value) {
  return JSON.parse(JSON.stringify(value || {}));
}

function safeSnapshot(context) {
  return {
    event: context.event ? { type: context.event.type, subject_type: context.event.subject_type, subject_id: context.event.subject_id } : null,
    subject: context.subject || null,
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
