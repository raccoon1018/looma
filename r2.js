const path = require('path');
const fs = require('fs');
const fsp = fs.promises;

let S3Client;
let PutObjectCommand;
try {
  ({ S3Client, PutObjectCommand } = require('@aws-sdk/client-s3'));
} catch {
  S3Client = null;
  PutObjectCommand = null;
}

let client = null;

function extractAccountId(value) {
  if (!value) return '';
  if (/^[a-f0-9]{32}$/i.test(value)) return value;
  try {
    const url = new URL(value);
    const host = url.hostname || '';
    const direct = host.match(/^([a-f0-9]{32})\.r2\.cloudflarestorage\.com$/i);
    if (direct) return direct[1];
    const pub = host.match(/^pub-([a-f0-9]{32})\.r2\.dev$/i);
    if (pub) return pub[1];
  } catch {
    /* ignore */
  }
  return '';
}

function getClient() {
  if (!S3Client) return null;
  const endpoint = process.env.LOOMA_R2_ENDPOINT;
  const accessKeyId = process.env.LOOMA_R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.LOOMA_R2_SECRET_ACCESS_KEY;
  const bucket = process.env.LOOMA_R2_BUCKET;
  if (!endpoint || !accessKeyId || !secretAccessKey || !bucket) return null;
  if (!client) {
    client = new S3Client({
      region: 'auto',
      endpoint,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
    });
  }
  return client;
}

async function uploadToStorage({ key, buffer, contentType }) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('uploadToStorage: buffer must be a Buffer instance');
  }

  const safeKey = key.replace(/[^a-zA-Z0-9/_\\.-]/g, '_');
  const s3 = getClient();
  if (s3) {
    const bucket = process.env.LOOMA_R2_BUCKET;
    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: safeKey,
        Body: buffer,
        ContentType: contentType || 'application/octet-stream',
      }),
    );
    const endpoint = (process.env.LOOMA_R2_ENDPOINT || '').replace(/\/$/, '');
    const accountFromEnv = (process.env.LOOMA_R2_ACCOUNT_ID || '').trim();
    const accountFromEndpoint = extractAccountId(endpoint);
    const publicBaseEnv = (process.env.LOOMA_R2_PUBLIC_BASE || '').replace(/\/$/, '');

    const candidates = [];
    if (publicBaseEnv) candidates.push(publicBaseEnv);
    const accountId = accountFromEnv || accountFromEndpoint;
    if (accountId && bucket) {
      candidates.push(`https://pub-${accountId}.r2.dev/${bucket}`);
      candidates.push(`https://${accountId}.r2.cloudflarestorage.com/${bucket}`);
    }
    if (endpoint && bucket) {
      const endpointUrl = (() => {
        try {
          return new URL(endpoint);
        } catch {
          return null;
        }
      })();
      if (endpoint.endsWith(`/${bucket}`)) {
        candidates.push(endpoint);
      } else if (endpointUrl) {
        candidates.push(`${endpointUrl.protocol}//${endpointUrl.host}/${bucket}`);
      } else {
        candidates.push(`${endpoint}/${bucket}`);
      }
    }

    const publicBase = candidates.find(Boolean) || '';
    const resolvedBase = publicBase.replace(/\/$/, '');
    return { url: resolvedBase ? `${resolvedBase}/${safeKey}` : `/${safeKey}` };
  }

  // Fallback: write to local uploads directory
  const uploadsRoot =
    process.env.LOOMA_UPLOADS_DIR || path.join(__dirname, 'uploads');
  const outPath = path.join(uploadsRoot, safeKey);
  await fsp.mkdir(path.dirname(outPath), { recursive: true });
  await fsp.writeFile(outPath, buffer);
  return { url: `/uploads/${safeKey}` };
}

module.exports = { uploadToStorage };
