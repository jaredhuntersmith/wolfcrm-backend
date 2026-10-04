import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCommsFixture } from "../../tests/helpers/comms-fixture.js";
import { recordingStorage } from "./storage.js";
import { transact } from "../access.js";

test(
  "recording adoption verifies private canonical bytes and source provenance",
  { timeout: 120000 },
  async (t) => {
    const f = await createCommsFixture(),
      { pool, companies, ids } = f;
    let bytes = 300;
    const env = {
      COMMS_RECORDING_S3_ENDPOINT: "https://storage.invalid",
      COMMS_RECORDING_S3_BUCKET: "private-test",
      COMMS_RECORDING_S3_ACCESS_KEY: "fake-test",
      COMMS_RECORDING_S3_SECRET: "fake-test",
      STORAGE_ENDPOINT: "https://storage.invalid",
      STORAGE_BUCKET: "private-test",
    };
    const adopt = recordingStorage(env, {
      client: { send: async () => ({ ContentLength: bytes }) },
    });
    const call = {
      id: randomUUID(),
      company_id: companies.a,
      conversation_id: "recording",
    };
    const record = () => ({
      id: randomUUID(),
      requested_by: ids.owner,
      object_key: "storage/test/" + randomUUID(),
      media: "audio",
      created_at: new Date(),
    });
    try {
      await pool.query(
        "INSERT INTO conversations(id,company_id,created_by,title) VALUES('recording',$1,$2,'Recording')",
        [companies.a, ids.owner],
      );
      // Root canonical source-ACL schema: use IF NOT EXISTS for fixture versions predating the root integration.
      await pool.query(
        "ALTER TABLE stored_files ADD COLUMN IF NOT EXISTS source_protected boolean NOT NULL DEFAULT false;CREATE TABLE IF NOT EXISTS comms_asset_conversation_sources(asset_id uuid PRIMARY KEY REFERENCES stored_files(id),company_id uuid NOT NULL,conversation_id text NOT NULL,capability text NOT NULL);",
      );
      await t.test("a different bucket cannot create canonical assets", () => {
        assert.equal(
          recordingStorage({ ...env, STORAGE_BUCKET: "other" }),
          null,
        );
      });
      await t.test(
        "missing or empty original never becomes a ready asset",
        async () => {
          bytes = 0;
          const r = record();
          await assert.rejects(
            transact(pool, (db) => adopt(db, call, r)),
            (e) => e.code === "recording_not_ready",
          );
          assert.equal(
            (await pool.query("SELECT 1 FROM stored_files WHERE id=$1", [r.id]))
              .rowCount,
            0,
          );
          bytes = 300;
        },
      );
      await t.test(
        "one asset with source-required access is created and duplicate delivery adds no bytes",
        async () => {
          const r = record();
          const asset = await transact(pool, (db) => adopt(db, call, r));
          assert.equal(asset.source_protected, true);
          assert.equal(asset.visibility, "private");
          assert.equal(asset.object_key, r.object_key);
          const same = await transact(pool, (db) => adopt(db, call, r));
          assert.equal(same.id, asset.id);
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM comms_asset_grants WHERE asset_id=$1",
                [asset.id],
              )
            ).rowCount,
            1,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM comms_asset_conversation_sources WHERE asset_id=$1",
                [asset.id],
              )
            ).rows[0].capability,
            "communications.calls",
          );
        },
      );
      await t.test(
        "a caller-chosen recording ID cannot adopt an unrelated asset",
        async () => {
          const id = await f.asset("alice", "audio");
          await assert.rejects(
            transact(pool, (db) => adopt(db, call, { ...record(), id })),
            (e) => e.code === "recording_asset_conflict",
          );
        },
      );
      await t.test(
        "Job Huddle recording adoption retains canonical job provenance",
        async () => {
          await pool.query(
            "CREATE TABLE comms_job_huddles(conversation_id text PRIMARY KEY,company_id uuid,job_id text)",
          );
          await pool.query(
            "INSERT INTO comms_job_huddles VALUES('recording',$1,'job-source')",
            [companies.a],
          );
          const r = record();
          const asset = await transact(pool, (db) => adopt(db, call, r));
          const source = (
            await pool.query(
              "SELECT * FROM comms_asset_provenance WHERE asset_id=$1",
              [asset.id],
            )
          ).rows[0];
          assert.equal(source.source_type, "job");
          assert.equal(source.source_id, "job-source");
        },
      );
      await t.test("quota prevents partial assets and grants", async () => {
        await pool.query(
          "UPDATE storage_accounts SET quota_bytes=350 WHERE user_id=$1",
          [ids.owner],
        );
        const r = record();
        await assert.rejects(
          transact(pool, (db) => adopt(db, call, r)),
          (e) => e.code === "recording_storage_quota",
        );
        assert.equal(
          (await pool.query("SELECT 1 FROM stored_files WHERE id=$1", [r.id]))
            .rowCount,
          0,
        );
      });
    } finally {
      await f.close();
    }
  },
);
