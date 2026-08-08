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
  ["job.completed", "Job Completed", "Schedule", "A scheduled job was marked complete.", ["job"], ["job.completed"]],
  ["sms.received", "SMS Received", "Phone", "An inbound SMS/MMS was received.", ["sms_conversation", "contact"], ["sms.received"]],
  ["sms.sent", "SMS Sent", "Phone", "An SMS/MMS was sent.", ["sms_conversation", "contact"], ["sms.sent"]],
  ["call.missed", "Missed Call", "Phone", "An inbound call was missed.", ["call"], ["call.missed"]],
  ["voicemail.received", "Voicemail Received", "Phone", "A voicemail recording was received.", ["voicemail"], ["voicemail.received"]],
  ["payment.succeeded", "Payment Succeeded", "Payments", "A Stripe payment succeeded.", ["payment", "contact"], ["payment.succeeded"]],
  ["payment.failed", "Payment Failed", "Payments", "A Stripe payment failed.", ["payment", "contact"], ["payment.failed"]],
  ["service_plan.created", "Service Plan Created", "Service Plans", "A service plan was created.", ["service_plan"], ["service_plan.created"]],
  ["service_plan.serviced", "Service Plan Serviced", "Service Plans", "A service plan was marked serviced.", ["service_plan"], ["service_plan.serviced"]],
  ["task.completed", "Task Completed", "Tasks", "A todo task was completed.", ["task"], ["task.completed"]]
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
  wired: !["contact.restored", "contact.assigned", "contact.reassigned", "contact.unassigned", "lead.assigned", "lead.reassigned", "pipeline.salesperson_assigned", "pipeline.salesperson_changed", "pipeline.salesperson_removed", "job.updated", "sms.sent"].includes(key)
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
  ["internal.send_message", "Send Internal Message", "Company Comms", "Sends a message to a conversation or channel.", ["generic"], ["default"]],
  ["job.create", "Create Job", "Schedule", "Creates a scheduled job.", ["contact"], ["default"]],
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
  "internal.send_message": executeInternalMessage,
  "job.create": executeJobCreate,
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
      return [commonText("body", "Message")];
    case "internal.send_message":
      return [commonText("body", "Message"), commonText("conversation_id", "Conversation ID"), commonText("channel_id", "Channel ID"), { key: "recipient_user_ids", label: "Recipients", type: "user_list" }];
    case "job.create":
      return [commonText("title", "Title"), { key: "start_at", label: "Start", type: "datetime" }, { key: "end_at", label: "End", type: "datetime" }, commonText("notes", "Notes")];
    case "webhook.send":
      return [commonText("url", "URL"), { key: "method", label: "Method", type: "select", options: ["GET", "POST", "PUT", "PATCH", "DELETE"] }, { key: "headers", label: "Headers", type: "json" }, { key: "body", label: "JSON Body", type: "json" }];
    case "automation.start":
      return [commonText("automation_id", "Automation ID")];
    default:
      return [];
  }
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
  `);
}

function installAutomationRoutes() {
  const { app, authRequired, requireEmployer } = ctx;

  app.get("/api/automations/catalog", authRequired, requireEmployer, (_req, res) => {
    res.json({
      triggers: triggerCatalog,
      actions: actionCatalog,
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
  const startNodes = resumeFromNodeId
    ? graph.edges.filter((e) => e.source_node_id === resumeFromNodeId && portMatches(e.source_port, incomingPort || "default")).sort(edgeSort).map((e) => graph.nodeById.get(e.target_node_id))
    : graph.nodes.filter((n) => n.node_type === "trigger" && triggerMatchesRun(n, run));
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
  return true;
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
    const value = resolveTemplate(node.config?.until || node.config?.datetime || "", context);
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error("invalid_wait_datetime");
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
  setInterval(() => ctx.pool.query(`UPDATE automation_definitions SET status = 'published', pause_until = NULL WHERE status = 'paused' AND pause_until IS NOT NULL AND pause_until <= now() AND active_version_id IS NOT NULL`).catch(() => {}), 60000).unref?.();
}

async function buildRunContext(run, options = {}) {
  const event = run.trigger_event_id ? (await ctx.pool.query(`SELECT * FROM automation_events WHERE id = $1`, [run.trigger_event_id])).rows[0] : null;
  const company = (await ctx.pool.query(`SELECT id, name, website, address, phone, email FROM companies WHERE id = $1`, [run.company_id])).rows[0] || {};
  const variables = Object.fromEntries((await ctx.pool.query(`SELECT name, value FROM automation_variables WHERE run_id = $1`, [run.id])).rows.map((r) => [r.name, r.value]));
  const nodeRows = options.slim ? [] : (await ctx.pool.query(`SELECT node_key, output_snapshot FROM automation_run_nodes WHERE run_id = $1 ORDER BY created_at ASC`, [run.id])).rows;
  const nodes = {};
  for (const row of nodeRows) nodes[row.node_key] = { output: row.output_snapshot || {} };
  const context = {
    company,
    event: event ? { id: event.id, type: event.event_type, payload: event.payload || {}, subject_type: event.subject_type, subject_id: event.subject_id } : {},
    variables,
    nodes,
    subject: { type: run.subject_type, id: run.subject_id }
  };
  if (!options.slim) {
    const subject = await loadSubject(run.company_id, run.subject_type, run.subject_id);
    if (run.subject_type) context[subjectContextKey(run.subject_type)] = subject || {};
    context.subject.object = subject || {};
  }
  return context;
}

async function loadSubject(companyId, subjectType, subjectId) {
  if (!subjectType || !subjectId) return null;
  if (subjectType === "contact") return (await ctx.pool.query(`SELECT id, name, phone, email, address, tags, job_type, u1, u2, u3, u4, u5 FROM contacts WHERE id::text = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "job") return (await ctx.pool.query(`SELECT * FROM schedule_events WHERE id = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "opportunity") return (await ctx.pool.query(`SELECT * FROM opportunities WHERE id = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "sms_conversation") return (await ctx.pool.query(`SELECT sc.* FROM sms_conversations sc JOIN phone_lines pl ON pl.id = sc.phone_line_id WHERE sc.id = $1 AND pl.company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "call") return (await ctx.pool.query(`SELECT * FROM phone_calls WHERE id = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "voicemail") return (await ctx.pool.query(`SELECT * FROM voicemails WHERE id = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "service_plan") return (await ctx.pool.query(`SELECT * FROM service_plans WHERE id::text = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "task") return (await ctx.pool.query(`SELECT tt.* FROM todo_tasks tt JOIN users u ON u.id = tt.user_id WHERE tt.id = $1 AND u.company_id = $2`, [subjectId, companyId])).rows[0] || null;
  if (subjectType === "payment") return (await ctx.pool.query(`SELECT * FROM payment_records WHERE id::text = $1 AND company_id = $2`, [subjectId, companyId])).rows[0] || null;
  return null;
}

function subjectContextKey(type) {
  return type === "sms_conversation" ? "sms" : type === "service_plan" ? "servicePlan" : type;
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
  const updated = await mutateContactTags(run.company_id, contactId, (existing) => [...new Set([...existing, ...tags])]);
  return { contact_id: contactId, tags: updated };
}

async function executeContactRemoveTag(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const tags = normalizeTags(resolveConfig(config.tags || config.tag || [], context)).map((t) => t.toLowerCase());
  const updated = await mutateContactTags(run.company_id, contactId, (existing) => existing.filter((t) => !tags.includes(t.toLowerCase())));
  return { contact_id: contactId, tags: updated };
}

async function executeContactUpdateFields(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const allowed = ["name", "phone", "email", "address", "job_type", "u1", "u2", "u3", "u4", "u5"];
  const updates = {};
  for (const field of allowed) if (config[field] != null) updates[field] = resolveTemplate(config[field], context);
  if (!Object.keys(updates).length) return { contact_id: contactId, updated: [] };
  const sets = Object.keys(updates).map((key, i) => `${key} = $${i + 3}`);
  const { rows } = await ctx.pool.query(
    `UPDATE contacts SET ${sets.join(", ")}, updated_at = now() WHERE id::text = $1 AND company_id = $2 RETURNING id`,
    [contactId, run.company_id, ...Object.values(updates)]
  );
  if (!rows.length) throw new Error("contact_not_found");
  return { contact_id: contactId, updated: Object.keys(updates) };
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
  const next = mutator(current).filter(Boolean);
  const type = (await ctx.pool.query(`SELECT data_type, udt_name FROM information_schema.columns WHERE table_name = 'contacts' AND column_name = 'tags' LIMIT 1`)).rows[0];
  const value = type?.udt_name?.startsWith("_") ? next : next.join(",");
  await ctx.pool.query(`UPDATE contacts SET tags = $3, updated_at = now() WHERE id::text = $1 AND company_id = $2`, [contactId, companyId, value]);
  return next;
}

function normalizeTags(value) {
  if (Array.isArray(value)) return value.flatMap(normalizeTags);
  if (value == null) return [];
  return String(value).split(",").map((t) => t.trim()).filter(Boolean);
}

async function executePipelineMoveStage(run, node, config) {
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const stageId = resolveTemplate(config.stage_id || "", context);
  const stage = await ctx.pool.query(`SELECT id FROM stages WHERE id = $1 AND company_id = $2`, [stageId, run.company_id]);
  if (!stage.rowCount) throw new Error("stage_not_found");
  const id = config.opportunity_id || randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO opportunities(id, user_id, company_id, contact_id, state, stage_id)
     VALUES($1, (SELECT owner_user_id FROM companies WHERE id = $2), $2, $3, 'stage', $4)
     ON CONFLICT(user_id, contact_id) DO UPDATE SET state = 'stage', stage_id = EXCLUDED.stage_id, updated_at = now()
     RETURNING id, stage_id`,
    [id, run.company_id, contactId, stageId]
  );
  return rows[0];
}

async function executeTaskCreate(run, node, config) {
  const context = await buildRunContext(run);
  const title = resolveTemplate(config.title || "Automation task", context);
  const assignee = await resolveCompanyUser(run.company_id, resolveTemplate(config.assigned_user_id || "", context));
  const due = resolveTemplate(config.due_date || config.due_at || "", context) || null;
  const id = randomUUID();
  const { rows } = await ctx.pool.query(
    `INSERT INTO todo_tasks(id, user_id, title, due_date, reminders, subtasks, completed, color_hex)
     VALUES($1,$2,$3,$4::timestamptz,'[]'::jsonb,'[]'::jsonb,false,$5) RETURNING id, title, due_date`,
    [id, assignee, title, due, config.color_hex || "#3478F6"]
  );
  return rows[0];
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
  const context = await buildRunContext(run);
  const contactId = await resolveContactId(run, context, config);
  const contact = (await ctx.pool.query(`SELECT phone FROM contacts WHERE id::text = $1 AND company_id = $2`, [contactId, run.company_id])).rows[0];
  const toNumber = normalizePhone(contact?.phone);
  if (!toNumber) throw new Error("contact_phone_required");
  const line = (await ctx.pool.query(`SELECT id, phone_number FROM phone_lines WHERE company_id = $1 AND active = true AND status = 'active' ORDER BY created_at ASC LIMIT 1`, [run.company_id])).rows[0];
  if (!line) throw new Error("phone_line_required");
  const body = resolveTemplate(config.body || "", context).slice(0, 1600);
  if (!body) throw new Error("sms_body_required");
  const client = ctx.createTwilioClient();
  if (!client) throw new Error("twilio_not_configured");
  const sent = await client.messages.create({ from: line.phone_number, to: toNumber, body, statusCallback: ctx.twilioPublicUrl("/webhooks/twilio/message-status") });
  const conv = (await ctx.pool.query(
    `INSERT INTO sms_conversations(phone_line_id, external_phone_number, contact_id, last_message_at)
     VALUES($1,$2,$3,now())
     ON CONFLICT(phone_line_id, external_phone_number) DO UPDATE SET contact_id = COALESCE(sms_conversations.contact_id, EXCLUDED.contact_id), last_message_at = now(), updated_at = now()
     RETURNING id`,
    [line.id, toNumber, contactId]
  )).rows[0];
  const msg = (await ctx.pool.query(
    `INSERT INTO sms_messages(conversation_id, twilio_message_sid, direction, from_number, to_number, body, message_status)
     VALUES($1,$2,'outbound',$3,$4,$5,$6) RETURNING id`,
    [conv.id, sent.sid || null, line.phone_number, toNumber, body, sent.status || "queued"]
  )).rows[0];
  return { message_id: msg.id, conversation_id: conv.id, twilio_message_sid: sent.sid };
}

function normalizePhone(value) {
  const s = (value || "").toString().trim();
  if (!s) return "";
  return s.startsWith("+") ? s : `+1${s.replace(/\D/g, "").slice(-10)}`;
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
  return { message_id: id, conversation_id: conversationId };
}

async function executeJobCreate(run, node, config) {
  const context = await buildRunContext(run);
  const owner = await resolveCompanyUser(run.company_id, config.assigned_user_id);
  const id = randomUUID();
  const title = resolveTemplate(config.title || "Automation job", context);
  const start = new Date(resolveTemplate(config.start_at || "", context) || Date.now());
  const end = new Date(resolveTemplate(config.end_at || "", context) || start.getTime() + 3600000);
  const contactId = config.contact_id ? resolveTemplate(config.contact_id, context) : (run.subject_type === "contact" ? run.subject_id : null);
  if (contactId) await validateSubject(run.company_id, "contact", contactId);
  const { rows } = await ctx.pool.query(
    `INSERT INTO schedule_events(id, user_id, company_id, created_by, title, start_at, end_at, color, notes, contact_id, reminder_minutes, services, service_items, sales_user_ids, worker_user_ids)
     VALUES($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,$10::jsonb,$11::jsonb)
     RETURNING id, title, start_at AS start, end_at AS "end"`,
    [id, owner, run.company_id, title, start.toISOString(), end.toISOString(), config.color || "#3478F6", resolveTemplate(config.notes || "", context) || null, contactId, JSON.stringify([owner]), JSON.stringify([])]
  );
  return rows[0];
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
