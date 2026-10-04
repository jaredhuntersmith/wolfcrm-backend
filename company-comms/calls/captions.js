import { randomUUID, timingSafeEqual } from "node:crypto";
import { loadActor, transact } from "../access.js";
import { fail, requireCapability, uuid, terminal } from "./domain.js";
export function createCaptionService({
  pool,
  provider,
  authorizeConversation,
  publish,
  env = process.env,
}) {
  const secret = env.COMMS_CAPTIONS_WORKER_SECRET || "";
  const configured =
    env.COMMS_CAPTIONS_ENABLED === "true" &&
    secret.length >= 32 &&
    provider.configured;
  const workerAuthorized = (header) => {
    const value = String(header || "").replace(/^Bearer /, "");
    return (
      secret.length >= 32 &&
      Buffer.byteLength(value) === Buffer.byteLength(secret) &&
      timingSafeEqual(Buffer.from(value), Buffer.from(secret))
    );
  };
  async function context(db, input, id, capability = "communications.calls") {
    const actor = await loadActor(db, input);
    requireCapability(actor, capability);
    const call = (
      await db.query(
        "SELECT * FROM comms_call_sessions WHERE id=$1 AND company_id=$2 FOR UPDATE",
        [uuid(id), actor.companyId],
      )
    ).rows[0];
    if (!call) fail(404, "call_unavailable");
    await authorizeConversation(db, actor, call.conversation_id, {
      capability,
    });
    if (call.meeting_id) {
      const meeting = (
        await db.query(
          "SELECT source_conversation_id FROM comms_meetings WHERE id=$1",
          [call.meeting_id],
        )
      ).rows[0];
      if (meeting?.source_conversation_id)
        await authorizeConversation(db, actor, meeting.source_conversation_id, {
          capability,
        });
    }
    const me = (
      await db.query(
        "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
        [call.id, actor.userId],
      )
    ).rows[0];
    if (!me || !["accepted", "admitted", "joined"].includes(me.state))
      fail(403, "active_participant_required");
    return { actor, call, me };
  }
  async function policy(db, run) {
    if (
      run.created_at &&
      (
        await db.query(
          "SELECT $1::timestamptz<date_trunc('month',now()) AS expired",
          [run.created_at],
        )
      ).rows[0].expired
    )
      fail(409, "caption_period_ended");
    const base = await context(
      db,
      { companyId: run.company_id, userId: run.requested_by },
      run.call_id,
      "communications.transcribe",
    );
    if (terminal(base.call.status)) fail(409, "call_ended");
    const settings = (
      await db.query(
        "SELECT * FROM comms_call_settings WHERE company_id=$1 FOR UPDATE",
        [run.company_id],
      )
    ).rows[0];
    if (!configured || !settings?.enabled || !settings.captions_enabled)
      fail(403, "captions_disabled");
    const used = Number(
      (
        await db.query(
          "SELECT COALESCE(sum(reserved_seconds),0) AS seconds FROM comms_caption_usage WHERE company_id=$1 AND created_at>=date_trunc('month',now())",
          [run.company_id],
        )
      ).rows[0].seconds,
    );
    if (used >= settings.monthly_caption_minutes * 60)
      fail(429, "caption_usage_limit");
    if (
      (
        await db.query(
          "SELECT 1 FROM comms_guest_sessions WHERE call_id=$1 AND state IN('admitted','joined')",
          [run.call_id],
        )
      ).rowCount
    )
      fail(409, "guest_caption_consent_unavailable");
    const people = (
      await db.query(
        `SELECT p.user_id,p.identity,u.display_name,COALESCE(s.consented,false) AS consented FROM comms_call_participants p JOIN users u ON u.id=p.user_id LEFT JOIN comms_caption_consents s ON s.run_id=$2 AND s.user_id=p.user_id WHERE p.call_id=$1 AND p.state IN('accepted','admitted','joined')`,
        [run.call_id, run.id],
      )
    ).rows;
    const recipients = [];
    for (const person of people) {
      const current = await context(
        db,
        { companyId: run.company_id, userId: person.user_id },
        run.call_id,
      );
      if (
        current.actor.isCompanyOwner ||
        current.actor.permissions.capabilities["communications.transcribe"] ===
          true
      )
        recipients.push(person.identity);
    }
    return {
      ...base,
      settings,
      people,
      recipients,
      all: people.length > 0 && people.every((p) => p.consented),
    };
  }
  const event = async (db, actor, call, run) =>
    publish(db, actor, call.conversation_id, "call.captions", run.id, {
      call_id: call.id,
    });
  const live = async (db, id) =>
    (
      await db.query(
        "SELECT * FROM comms_caption_runs WHERE call_id=$1 ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        [id],
      )
    ).rows[0];
  async function stop(db, run, code = null) {
    await db.query(
      "UPDATE comms_caption_runs SET state='stopping',error_code=$2,lease_expires_at=NULL,updated_at=now() WHERE id=$1 AND state NOT IN('stopped','failed')",
      [run.id, code],
    );
  }
  const service = {
    configured,
    workerAuthorized,
    async get(a, id) {
      return transact(pool, async (db) => {
        const { actor, call } = await context(db, a, id),
          run = await live(db, id);
        const settings = (
          await db.query(
            "SELECT captions_enabled FROM comms_call_settings WHERE company_id=$1",
            [actor.companyId],
          )
        ).rows[0];
        const people = run
          ? (
              await db.query(
                `SELECT p.user_id,p.identity,u.display_name,COALESCE(s.consented,false) AS consented FROM comms_call_participants p JOIN users u ON u.id=p.user_id LEFT JOIN comms_caption_consents s ON s.run_id=$2 AND s.user_id=p.user_id WHERE p.call_id=$1 AND p.state IN('accepted','admitted','joined')`,
                [id, run.id],
              )
            ).rows
          : [];
        const canView =
          actor.isCompanyOwner ||
          actor.permissions.capabilities["communications.transcribe"] === true;
        let state = run?.state || "off";
        if (
          run &&
          ["active", "starting"].includes(state) &&
          people.some((p) => !p.consented)
        )
          state = "consent";
        return {
          configured,
          enabled: settings?.captions_enabled === true,
          status: state,
          run_id: run?.id || null,
          agent_identity: canView ? run?.agent_identity : null,
          my_consent:
            people.find((p) => p.user_id === actor.userId)?.consented || false,
          consented_count: people.filter((p) => p.consented).length,
          participant_count: people.length,
          can_start: call.host_user_id === actor.userId && canView,
          can_view: canView,
          error_code: run?.error_code || null,
          participants: canView
            ? people.map(({ identity, display_name }) => ({
                identity,
                display_name,
              }))
            : [],
        };
      });
    },
    async start(a, id, body = {}) {
      return transact(pool, async (db) => {
        const { actor, call } = await context(
          db,
          a,
          id,
          "communications.transcribe",
        );
        if (actor.userId !== call.host_user_id) fail(403, "host_required");
        if (terminal(call.status)) fail(409, "call_ended");
        if (!configured) fail(503, "captions_not_configured");
        const previous = await live(db, id);
        if (previous && !["stopped", "failed"].includes(previous.state))
          return { run_id: previous.id };
        const run = {
          id: uuid(body.id || randomUUID()),
          call_id: id,
          company_id: actor.companyId,
          requested_by: actor.userId,
        };
        run.agent_identity = "cc_" + run.id.replaceAll("-", "");
        await db.query(
          "INSERT INTO comms_caption_runs(id,call_id,company_id,requested_by,agent_identity) VALUES($1,$2,$3,$4,$5)",
          [run.id, id, actor.companyId, actor.userId, run.agent_identity],
        );
        await policy(db, run);
        await db.query(
          "INSERT INTO comms_caption_usage(run_id,company_id) VALUES($1,$2)",
          [run.id, actor.companyId],
        );
        await event(db, actor, call, run);
        return { run_id: run.id };
      });
    },
    async consent(a, id, body) {
      return transact(pool, async (db) => {
        const { actor, call } = await context(db, a, id),
          run = await live(db, id);
        if (
          !run ||
          run.id !== uuid(body.run_id) ||
          !["consent", "starting", "active"].includes(run.state)
        )
          fail(409, "caption_run_unavailable");
        if (typeof body.consented !== "boolean") fail(400, "invalid_consent");
        await db.query(
          "INSERT INTO comms_caption_consents(run_id,user_id,consented) VALUES($1,$2,$3) ON CONFLICT(run_id,user_id) DO UPDATE SET consented=$3,updated_at=now()",
          [run.id, actor.userId, body.consented],
        );
        if (!body.consented) await stop(db, run, "consent_withdrawn");
        await event(db, actor, call, run);
        return { ok: true };
      });
    },
    async stop(a, id) {
      return transact(pool, async (db) => {
        const { actor, call } = await context(db, a, id);
        const run = await live(db, id);
        if (run) {
          await stop(db, run);
          await event(db, actor, call, run);
        }
        return { ok: true };
      });
    },
    async lease(body) {
      return transact(pool, async (db) => {
        const id = uuid(body.run_id),
          worker = uuid(body.worker_id);
        const lookup = (
          await db.query("SELECT call_id FROM comms_caption_runs WHERE id=$1", [
            id,
          ])
        ).rows[0];
        if (lookup)
          await db.query(
            "SELECT id FROM comms_call_sessions WHERE id=$1 FOR UPDATE",
            [lookup.call_id],
          );
        const run = (
          await db.query(
            "SELECT * FROM comms_caption_runs WHERE id=$1 FOR UPDATE",
            [id],
          )
        ).rows[0];
        if (!run || !["starting", "active"].includes(run.state))
          return {
            active: false,
            status: run?.state || "unavailable",
            lease_seconds: 0,
          };
        if (run.worker_id && run.worker_id !== worker)
          fail(409, "caption_worker_claimed");
        try {
          const current = await policy(db, run);
          if (!current.all || !current.recipients.length) {
            await db.query(
              "UPDATE comms_caption_runs SET lease_expires_at=NULL,worker_id=$2,updated_at=now() WHERE id=$1",
              [id, worker],
            );
            return { active: false, status: "consent", lease_seconds: 0 };
          }
          const used = Number(
            (
              await db.query(
                "SELECT COALESCE(sum(reserved_seconds),0) AS seconds FROM comms_caption_usage WHERE company_id=$1 AND created_at>=date_trunc('month',now())",
                [run.company_id],
              )
            ).rows[0].seconds,
          );
          const now = Date.now(),
            until = now + 3000,
            previous = run.lease_expires_at
              ? Math.max(now, +new Date(run.lease_expires_at))
              : now;
          const seconds =
            Math.max(0, (until - previous) / 1000) * current.people.length;
          const remaining =
            current.settings.monthly_caption_minutes * 60 - used;
          if (seconds > remaining) fail(429, "caption_usage_limit");
          await db.query(
            "UPDATE comms_caption_runs SET state=CASE WHEN agent_joined_at IS NULL THEN 'starting' ELSE 'active' END,worker_id=$2,lease_expires_at=$3,updated_at=now() WHERE id=$1",
            [id, worker, new Date(until)],
          );
          await db.query(
            "UPDATE comms_caption_usage SET reserved_seconds=reserved_seconds+$2 WHERE run_id=$1",
            [id, seconds],
          );
          return {
            active: true,
            status: run.agent_joined_at ? "active" : "starting",
            lease_seconds: 3,
            call_id: run.call_id,
            room_name: current.call.room_name,
            run_id: id,
            agent_identity: run.agent_identity,
            participants: current.people.map(({ identity, display_name }) => ({
              identity,
              display_name,
            })),
            recipients: current.recipients,
            remaining_seconds:
              3 + Math.max(0, remaining - seconds) / current.people.length,
          };
        } catch (error) {
          if (!error.status) throw error;
          await stop(db, run, error.code);
          return { active: false, status: "stopping", lease_seconds: 0 };
        }
      });
    },
    async failure(body) {
      return transact(pool, async (db) => {
        const run = (
          await db.query(
            "SELECT * FROM comms_caption_runs WHERE id=$1 FOR UPDATE",
            [uuid(body.run_id)],
          )
        ).rows[0];
        if (!run || (run.worker_id && run.worker_id !== uuid(body.worker_id)))
          fail(404, "caption_run_unavailable");
        uuid(body.worker_id);
        await stop(
          db,
          run,
          ["stt_unavailable", "caption_worker_failed"].includes(body.code)
            ? body.code
            : "caption_worker_failed",
        );
        return { ok: true };
      });
    },
    async acceptAgent(db, call, identity) {
      const run = (
        await db.query(
          "SELECT * FROM comms_caption_runs WHERE call_id=$1 AND agent_identity=$2 AND state IN('starting','active')",
          [call.id, identity],
        )
      ).rows[0];
      if (!run) return false;
      try {
        if (!(await policy(db, run)).all) return false;
        await db.query(
          "UPDATE comms_caption_runs SET agent_joined_at=now(),state=CASE WHEN worker_id IS NULL THEN 'starting' ELSE 'active' END WHERE id=$1 AND state IN('starting','active')",
          [run.id],
        );
        return true;
      } catch (error) {
        if (!error.status) throw error;
        return false;
      }
    },
    async reconcile() {
      const candidates = (
        await pool.query(
          "SELECT id FROM comms_caption_runs WHERE state IN('consent','starting','active','stopping') ORDER BY created_at LIMIT 20",
        )
      ).rows;
      for (const candidate of candidates) {
        let work;
        await transact(pool, async (db) => {
          const lookup = (
            await db.query(
              "SELECT call_id FROM comms_caption_runs WHERE id=$1",
              [candidate.id],
            )
          ).rows[0];
          if (!lookup) return;
          if (
            !(
              await db.query(
                "SELECT id FROM comms_call_sessions WHERE id=$1 FOR UPDATE SKIP LOCKED",
                [lookup.call_id],
              )
            ).rowCount
          )
            return;
          const run = (
            await db.query(
              "SELECT * FROM comms_caption_runs WHERE id=$1 FOR UPDATE",
              [candidate.id],
            )
          ).rows[0];
          if (!run) return;
          const call = (
            await db.query("SELECT * FROM comms_call_sessions WHERE id=$1", [
              run.call_id,
            ])
          ).rows[0];
          if (run.state !== "stopping")
            try {
              const current = await policy(db, run);
              if (run.state === "consent" && current.all) {
                await db.query(
                  "UPDATE comms_caption_runs SET state='starting',updated_at=now() WHERE id=$1",
                  [run.id],
                );
                run.state = "starting";
                run.updated_at = new Date();
              }
              if (
                ["starting", "active"].includes(run.state) &&
                run.worker_id &&
                ((run.lease_expires_at &&
                  +new Date(run.lease_expires_at) < Date.now() - 3000) ||
                  Date.now() - +new Date(run.updated_at) > 10000)
              )
                fail(409, "caption_worker_expired");
              if (
                run.state === "starting" &&
                Date.now() - +new Date(run.updated_at) > 30000
              )
                fail(409, "caption_worker_unavailable");
              if (!current.all && run.lease_expires_at)
                await db.query(
                  "UPDATE comms_caption_runs SET lease_expires_at=NULL WHERE id=$1",
                  [run.id],
                );
            } catch (error) {
              if (!error.status) throw error;
              await stop(db, run, error.code);
              run.state = "stopping";
            }
          if (run.state === "stopping") work = { run, call };
          else if (
            run.state === "starting" &&
            !run.dispatch_id &&
            (!run.dispatch_claimed_at ||
              Date.now() - +new Date(run.dispatch_claimed_at) > 15000)
          ) {
            await db.query(
              "UPDATE comms_caption_runs SET dispatch_claimed_at=now() WHERE id=$1",
              [run.id],
            );
            work = { run, call };
          }
        });
        if (!work) continue;
        const { run, call } = work;
        try {
          if (run.state === "stopping") {
            const dispatches = await provider.captionDispatches(call);
            for (const item of dispatches)
              if (
                item.id === run.dispatch_id ||
                item.metadata === JSON.stringify({ caption_run_id: run.id })
              )
                await provider.stopCaptions(call, item.id);
            await provider.remove(call, run.agent_identity);
            await pool.query(
              "UPDATE comms_caption_runs SET state=CASE WHEN error_code IS NULL OR error_code='consent_withdrawn' THEN 'stopped' ELSE 'failed' END,ended_at=now(),lease_expires_at=NULL WHERE id=$1 AND state='stopping'",
              [run.id],
            );
          } else {
            const result = await provider.startCaptions(call, run);
            const updated = await pool.query(
              "UPDATE comms_caption_runs SET dispatch_id=$2 WHERE id=$1 AND state IN('starting','active') RETURNING id",
              [run.id, result.id],
            );
            if (!updated.rowCount) {
              await provider.stopCaptions(call, result.id);
              await provider.remove(call, run.agent_identity);
            }
          }
        } catch {
          await pool.query(
            "UPDATE comms_caption_runs SET error_code='caption_provider_unavailable' WHERE id=$1",
            [run.id],
          );
        }
      }
    },
  };
  return service;
}
