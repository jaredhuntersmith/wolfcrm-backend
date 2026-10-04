import { S3Client, ListMultipartUploadsCommand, CreateMultipartUploadCommand, UploadPartCommand, ListPartsCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
export const PART_SIZE = 16 * 1024 * 1024;
export const ACCESS_SECONDS = 300;
export function createStorageBucket(env = process.env) {
  const endpoint = env.STORAGE_ENDPOINT || env.MEDIA_ENDPOINT || env.AWS_ENDPOINT_URL;
  const bucket = env.STORAGE_BUCKET || env.MEDIA_BUCKET || env.AWS_S3_BUCKET_NAME;
  const accessKeyId = env.STORAGE_ACCESS_KEY_ID || env.MEDIA_ACCESS_KEY_ID || env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = env.STORAGE_SECRET_ACCESS_KEY || env.MEDIA_SECRET_ACCESS_KEY || env.AWS_SECRET_ACCESS_KEY;
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;
  const client = new S3Client({ endpoint, region: env.STORAGE_REGION || env.MEDIA_REGION || env.AWS_DEFAULT_REGION || 'auto', forcePathStyle: true, credentials: { accessKeyId, secretAccessKey }, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });
  const legacyEndpoint=env.MEDIA_ENDPOINT||env.AWS_ENDPOINT_URL, legacyBucket=env.MEDIA_BUCKET||env.AWS_S3_BUCKET_NAME;
  const legacyKey=env.MEDIA_ACCESS_KEY_ID||env.AWS_ACCESS_KEY_ID,legacySecret=env.MEDIA_SECRET_ACCESS_KEY||env.AWS_SECRET_ACCESS_KEY;
  const legacyClient=legacyEndpoint&&legacyBucket&&legacyKey&&legacySecret?new S3Client({endpoint:legacyEndpoint,region:env.MEDIA_REGION||env.AWS_DEFAULT_REGION||'auto',forcePathStyle:true,credentials:{accessKeyId:legacyKey,secretAccessKey:legacySecret}}):null;
  const deliveryClient=file=>{if(file.storage_provider!=='legacy_media')return client;if(!legacyClient)throw Object.assign(new Error('Legacy storage is not configured.'),{code:'legacy_storage_unavailable'});return legacyClient;};
  const args = file => ({ Bucket: file.storage_provider==='legacy_media'?legacyBucket:bucket, Key: file.object_key });
  let orphanMarker;
  return {
    async abandonedUploads() {
      const page=await client.send(new ListMultipartUploadsCommand({Bucket:bucket,Prefix:'storage/',MaxUploads:100,KeyMarker:orphanMarker?.key,UploadIdMarker:orphanMarker?.upload}));
      orphanMarker=page.IsTruncated?{key:page.NextKeyMarker,upload:page.NextUploadIdMarker}:undefined;
      return (page.Uploads||[]).filter(u=>new Date(u.Initiated).getTime()<Date.now()-24*60*60*1000).map(u=>({object_key:u.Key,upload_id:u.UploadId}));
    },
    async begin(file) { return (await client.send(new CreateMultipartUploadCommand({ ...args(file), ContentType: file.mime_type, Metadata: { 'wolf-file-id': file.id, 'wolf-owner-id': file.owner_user_id } }))).UploadId; },
    async part(file, number, size) { return getSignedUrl(client, new UploadPartCommand({ ...args(file), UploadId: file.upload_id, PartNumber: number, ContentLength: size }), { expiresIn: 900 }); },
    async parts(file) {
      let marker; const parts = [];
      do { const page = await client.send(new ListPartsCommand({ ...args(file), UploadId: file.upload_id, PartNumberMarker: marker })); parts.push(...(page.Parts || [])); marker = page.IsTruncated ? page.NextPartNumberMarker : undefined; } while(marker);
      return parts;
    },
    async complete(file, parts) { await client.send(new CompleteMultipartUploadCommand({ ...args(file), UploadId: file.upload_id, MultipartUpload: { Parts: parts.map(p => ({ ETag:p.ETag, PartNumber:p.PartNumber })) } })); },
    async head(file) { try { return await deliveryClient(file).send(new HeadObjectCommand(args(file))); } catch(e) { if (e.$metadata?.httpStatusCode === 404) return null; throw e; } },
    async abort(file) { if (!file.upload_id) return; try { await client.send(new AbortMultipartUploadCommand({ ...args(file), UploadId:file.upload_id })); } catch(e) { if (e.name !== 'NoSuchUpload') throw e; } },
    async remove(file) { await deliveryClient(file).send(new DeleteObjectCommand(args(file))); },
    async access(file, download) { return getSignedUrl(deliveryClient(file), new GetObjectCommand({ ...args(file), ResponseContentDisposition: `${download ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(file.original_filename).replace(/'/g,'%27')}`, ResponseCacheControl: 'private, no-store' }), { expiresIn: ACCESS_SECONDS }); }
  };
}
