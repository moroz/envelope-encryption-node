import { DecryptCommand, KMSClient } from "@aws-sdk/client-kms";
import { readFile } from "node:fs";
import { promisify } from "node:util";
import { ENCRYPTION_KEY_ID } from "./config.ts";

const readFilePromise = promisify(readFile);
const input = await readFilePromise(process.stdin.fd);

if (input.length === 0) {
  console.error("Failed to read from standard input.");
  process.exit(1);
}

const versionMarker = input.readUint8();
if (versionMarker !== 0x01) {
  const versionMarkerHex = versionMarker.toString(16).padStart(2, "0");
  console.error(`Unsupported version 0x${versionMarkerHex}.`);
  process.exit(1);
}

const keyLength = input.readUint16BE(1);
const wrappedKey = input.subarray(3, 3 + keyLength);
if (wrappedKey.byteLength !== keyLength) {
  console.error(
    `Failed to read wrapped key from input: Want ${keyLength} bytes, got ${wrappedKey.byteLength}.`,
  );
  process.exit(1);
}

const iv = input.subarray(3 + keyLength, 3 + keyLength + 12);
if (iv.byteLength !== 12) {
  console.error("Input too short.");
  process.exit(1);
}

const ciphertext = input.subarray(3 + keyLength + 12);

const kmsClient = new KMSClient();
const unwrappedKey = await kmsClient.send(
  new DecryptCommand({
    CiphertextBlob: wrappedKey,
    KeyId: ENCRYPTION_KEY_ID,
  }),
);

const decryptionKey = await crypto.subtle.importKey(
  "raw",
  unwrappedKey.Plaintext as Uint8Array<ArrayBuffer>,
  "AES-GCM",
  false,
  ["decrypt"],
);

const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, decryptionKey, ciphertext);

process.stdout.write(new Uint8Array(plaintext));
