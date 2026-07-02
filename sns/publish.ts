import { hmacSha256, sha256Hex } from "../../lib-ts/security/conversions";
import { SnsConfig } from "../types";

async function publishToSns(config: SnsConfig, subject: string, message: string): Promise<void> {
  // NOTE: This is a temporary solution to be used in place of the sns package (@aws-sdk/client-sns), as it doesn't work properly at the moment in this setup.
  const { region, accessKeyId, secretAccessKey, topicArn } = config;
  const host = `sns.${region}.amazonaws.com`;
  const url = `https://${host}/`;
  const body = new URLSearchParams({
    Action: 'Publish',
    TopicArn: topicArn,
    Subject: subject,
    Message: message,
    Version: '2010-03-31',
  }).toString();

  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${region}/sns/aws4_request`;

  const payloadHash = await sha256Hex(body);
  const canonicalHeaders = `content-type:application/x-www-form-urlencoded\nhost:${host}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'content-type;host;x-amz-date';
  const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256Hex(canonicalRequest)}`;

  const kDate = await hmacSha256(new TextEncoder().encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, 'sns');
  const kSigning = await hmacSha256(kService, 'aws4_request');
  const signatureBuffer = new Uint8Array(await hmacSha256(kSigning, stringToSign));
  const signature = [...signatureBuffer].map((b) => b.toString(16).padStart(2, '0')).join('');

  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Amz-Date': amzDate,
      Authorization: authorization,
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`SNS Publish failed (${res.status}): ${text}`);
  }
}
