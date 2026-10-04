import { S3Client, HeadObjectCommand } from "@aws-sdk/client-s3";
import { fail } from "./domain.js";
export function recordingStorage(
  env = process.env,
  { client: injectedClient } = {},
) {
  const endpoint = env.COMMS_RECORDING_S3_ENDPOINT,
    bucket = env.COMMS_RECORDING_S3_BUCKET;
  if (
    !endpoint ||
    !bucket ||
    !env.COMMS_RECORDING_S3_ACCESS_KEY ||
    !env.COMMS_RECORDING_S3_SECRET
  )
    return null;
  // Canonical storage endpoints must be able to deliver the same bucket's bytes.
  const mediaEndpoint =
    env.STORAGE_ENDPOINT || env.MEDIA_ENDPOINT || env.AWS_ENDPOINT_URL;
  const mediaBucket =
    env.STORAGE_BUCKET || env.MEDIA_BUCKET || env.AWS_S3_BUCKET_NAME;
  if (endpoint !== mediaEndpoint || bucket !== mediaBucket) return null;
  const client =
    injectedClient ||
    new S3Client({
      endpoint,
      region: env.COMMS_RECORDING_S3_REGION || "auto",
      forcePathStyle: true,
      credentials: {
        accessKeyId: env.COMMS_RECORDING_S3_ACCESS_KEY,
        secretAccessKey: env.COMMS_RECORDING_S3_SECRET,
      },
    });
  const protect = async (db, file, call, recording) => {
    await db.query(
      `INSERT INTO comms_asset_grants(asset_id,conversation_id,company_id,granted_by,source_type,source_id) VALUES($1,$2,$3,$4,'recording',$5) ON CONFLICT DO NOTHING`,
      [
        file.id,
        call.conversation_id,
        call.company_id,
        recording.requested_by,
        recording.id,
      ],
    );
    await db.query(
      "INSERT INTO comms_asset_conversation_sources(asset_id,company_id,conversation_id,capability) VALUES($1,$2,$3,'communications.calls') ON CONFLICT(asset_id) DO NOTHING",
      [file.id, call.company_id, call.conversation_id],
    );
    const mapping = (
      await db.query("SELECT to_regclass('comms_job_huddles') AS name")
    ).rows[0];
    if (mapping.name) {
      let source = call.conversation_id;
      if (call.meeting_id)
        source =
          (
            await db.query(
              "SELECT source_conversation_id FROM comms_meetings WHERE id=$1",
              [call.meeting_id],
            )
          ).rows[0]?.source_conversation_id || source;
      const job = (
        await db.query(
          "SELECT job_id FROM comms_job_huddles WHERE conversation_id=$1 AND company_id=$2",
          [source, call.company_id],
        )
      ).rows[0];
      if (job)
        await db.query(
          "INSERT INTO comms_asset_provenance(asset_id,company_id,source_type,source_id,context_type) VALUES($1,$2,'job',$3,'job') ON CONFLICT(asset_id) DO NOTHING",
          [file.id, call.company_id, job.job_id],
        );
    }
  };
  return async function adopt(db, call, recording) {
    const head = await client.send(
      new HeadObjectCommand({ Bucket: bucket, Key: recording.object_key }),
    );
    if (!Number.isSafeInteger(head.ContentLength) || head.ContentLength <= 0)
      fail(409, "recording_not_ready");
    const prior = (
      await db.query("SELECT * FROM stored_files WHERE id=$1", [recording.id])
    ).rows[0];
    if (prior) {
      if (
        prior.owner_user_id !== recording.requested_by ||
        prior.company_id !== call.company_id ||
        prior.object_key !== recording.object_key ||
        prior.cloud_status !== "active"
      )
        fail(409, "recording_asset_conflict");
      await protect(db, prior, call, recording);
      return prior;
    }
    await db.query(
      "INSERT INTO storage_accounts(user_id,quota_bytes) VALUES($1,$2) ON CONFLICT DO NOTHING",
      [
        recording.requested_by,
        Number(env.STORAGE_DEFAULT_QUOTA_BYTES) || 25 * 1024 ** 3,
      ],
    );
    const account = (
      await db.query(
        "SELECT quota_bytes FROM storage_accounts WHERE user_id=$1 FOR UPDATE",
        [recording.requested_by],
      )
    ).rows[0];
    const used = Number(
      (
        await db.query(
          "SELECT (SELECT COALESCE(sum(byte_size),0) FROM stored_files WHERE owner_user_id=$1 AND cloud_status<>'deleted')+(SELECT COALESCE(sum(byte_size),0) FROM storage_thumbnails WHERE owner_user_id=$1 AND cloud_status<>'deleted') AS bytes",
          [recording.requested_by],
        )
      ).rows[0].bytes,
    );
    if (used + head.ContentLength > Number(account.quota_bytes))
      fail(413, "recording_storage_quota");
    const file = (
      await db.query(
        `INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,extension,category,byte_size,cloud_status,metadata_json,uploaded_at,source_protected) VALUES($1,$2,$2,$3,$4,$4,$5,$6,$7,$8,$9,'active',$10,now(),true) RETURNING *`,
        [
          recording.id,
          recording.requested_by,
          call.company_id,
          `Meeting recording ${new Date(recording.created_at).toISOString().slice(0, 10)}.${recording.media === "audio" ? "ogg" : "mp4"}`,
          recording.object_key,
          recording.media === "audio" ? "audio/ogg" : "video/mp4",
          recording.media === "audio" ? "ogg" : "mp4",
          recording.media === "audio" ? "audio" : "video",
          head.ContentLength,
          { call_id: call.id, recording_id: recording.id },
        ],
      )
    ).rows[0];
    await protect(db, file, call, recording);
    return file;
  };
}
