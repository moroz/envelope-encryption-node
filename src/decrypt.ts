import { DecryptCommand, KMSClient } from "@aws-sdk/client-kms";
import { promisify } from "node:util";
import { readFile } from "node:fs";
import { ENCRYPTION_KEY_ID } from "./config.ts";

const kmsClient = new KMSClient();

const readFilePromise = promisify(readFile);
const fileContents = await readFilePromise(0);

const keySizeBuffer = fileContents.subarray(0, 2);
const keySize = keySizeBuffer.readUint16BE();

const key = fileContents.subarray(2, 2 + keySize);
if (key.byteLength != keySize) {
  console.error(`Failed to read ${keySize} bytes from input stream.`);
  process.exit(1);
}

const decryptResult = await kmsClient
  .send(
    new DecryptCommand({
      KeyId: ENCRYPTION_KEY_ID,
      CiphertextBlob: key,
    }),
  )
  .catch((e) => {
    console.error(`Failed to decrypt key`, e);
    process.exit(1);
  });

const decryptionKey = await crypto.subtle.importKey(
  "raw",
  decryptResult.Plaintext as Uint8Array<ArrayBuffer>,
  "AES-GCM",
  false,
  ["decrypt"],
);

const iv = fileContents.subarray(2 + keySize, 2 + keySize + 12);
const ciphertext = fileContents.subarray(2 + keySize + 12);

const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, decryptionKey, ciphertext);

process.stdout.write(Buffer.from(decrypted));
