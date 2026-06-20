import { promisify } from "node:util";
import { readFile } from "node:fs";
import { GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";

if (process.stdout.isTTY) {
  console.error("Error: cannot write binary output to a terminal. Pipe the output to a file.");
  process.exit(2);
}

const readFilePromise = promisify(readFile);
const plaintext = await readFilePromise(process.stdin.fd);

const ENCRYPTION_KEY_ID = process.env.ENCRYPTION_KEY_ID!;
const kmsClient = new KMSClient();

const generateKeyResponse = await kmsClient.send(
  new GenerateDataKeyCommand({
    KeyId: ENCRYPTION_KEY_ID,
    KeySpec: "AES_256",
  }),
);

const encryptionKey = await crypto.subtle.importKey(
  "raw",
  generateKeyResponse.Plaintext as Uint8Array<ArrayBuffer>,
  "AES-GCM",
  false,
  ["encrypt"],
);

const iv = crypto.getRandomValues(new Uint8Array(12));

const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, plaintext);

const header = Buffer.alloc(3);
header.writeUint8(1);
header.writeUint16BE(generateKeyResponse.CiphertextBlob!.byteLength, 1);

const chunks = [
  header,
  generateKeyResponse.CiphertextBlob as Uint8Array<ArrayBuffer>,
  iv,
  ciphertext,
];

for (const chunk of chunks) {
  process.stdout.write(new Uint8Array(chunk));
}
