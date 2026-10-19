<!-- guide:messages version:1 -->
# Customer messages and internal Comms

Customer SMS search uses crm_search customer_messages and crm_customer_history. assistant_customer_message submits one text to an existing authorized conversation through the phone service, after exact configured approval; no outbound call is exposed. Each external request has a durable request_id and outcome receipt. Submitted is not delivered: provider callbacks supply delivery status. If the response is lost, the task is interrupted and must be reconciled with Messages before another send. communications_send posts internally through the existing Comms service with membership checks.
