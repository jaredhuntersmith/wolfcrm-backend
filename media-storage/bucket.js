import { S3Client, CreateMultipartUploadCommand, UploadPartCommand, ListPartsCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
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
  const args = file => ({ Bucket: bucket, Key: file.object_key });
  return {
    async begin(file) { return (await client.send(new CreateMultipartUploadCommand({ ...args(file), ContentType: file.mime_type, Metadata: { 'wolf-file-id': file.id, 'wolf-owner-id': file.owner_user_id } }))).UploadId; },
    async part(file, number, size) { return getSignedUrl(client, new UploadPartCommand({ ...args(file), UploadId: file.upload_id, PartNumber: number, ContentLength: size }), { expiresIn: 900 }); },
    async parts(file) {
      let marker; const parts = [];
      do { const page = await client.send(new ListPartsCommand({ ...args(file), UploadId: file.upload_id, PartNumberMarker: marker })); parts.push(...(page.Parts || [])); marker = page.IsTruncated ? page.NextPartNumberMarker : undefined; } while(marker);
      return parts;
    },
    async complete(file, parts) { await client.send(new CompleteMultipartUploadCommand({ ...args(file), UploadId: file.upload_id, MultipartUpload: { Parts: parts.map(p => ({ ETag:p.ETag, PartNumber:p.PartNumber })) } })); },
    async head(file) { try { return await client.send(new HeadObjectCommand(args(file))); } catch(e) { if (e.$metadata?.httpStatusCode === 404) return null; throw e; } },
    async abort(file) { if (!file.upload_id) return; try { await client.send(new AbortMultipartUploadCommand({ ...args(file), UploadId:file.upload_id })); } catch(e) { if (e.name !== 'NoSuchUpload') throw e; } },
    async remove(file) { await client.send(new DeleteObjectCommand(args(file))); },
    async access(file, download) { return getSignedUrl(client, new GetObjectCommand({ ...args(file), ResponseContentDisposition: `${download ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(file.original_filename).replace(/'/g,'%27')}`, ResponseCacheControl: 'private, no-store' }), { expiresIn: ACCESS_SECONDS }); }
  };
}
