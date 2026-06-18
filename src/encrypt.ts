import { GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { readFile } from "node:fs";
import { promisify } from "node:util";
import { ENCRYPTION_KEY_ID } from "./config.js";

const kmsClient = new KMSClient();

const readFilePromise = promisify(readFile);
const fileContents = await readFilePromise(0);

let dek, generateDataKeyResponse;

try {
  generateDataKeyResponse = await kmsClient.send(
    new GenerateDataKeyCommand({
      KeyId: ENCRYPTION_KEY_ID,
      KeySpec: "AES_256",
    }),
  )!;
  dek = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(generateDataKeyResponse.Plaintext!),
    "AES-GCM",
    false,
    ["encrypt"],
  );
} catch (e) {
  console.error(`Failed to generate a DEK`, e);
  process.exit(1);
}

const iv = crypto.getRandomValues(new Uint8Array(12));

const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, fileContents);

const keyLength = Buffer.alloc(2);
keyLength.writeUint16BE(generateDataKeyResponse.CiphertextBlob?.byteLength!);

process.stdout.write(keyLength);
process.stdout.write(generateDataKeyResponse.CiphertextBlob!);
process.stdout.write(iv);
process.stdout.write(Buffer.from(ciphertext));
