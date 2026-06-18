import { GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";

function mustGetenv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`FATAL: Environment variable ${name} is not set!`);
    process.exit(1);
  }
  return value;
}

const ENCRYPTION_KEY_ID = mustGetenv("ENCRYPTION_KEY_ID");

const kmsClient = new KMSClient();

const generateDataKeyResponse = await kmsClient.send(
  new GenerateDataKeyCommand({
    KeyId: ENCRYPTION_KEY_ID,
    KeySpec: "AES_256",
  }),
);
console.log({ generateDataKeyResponse });
