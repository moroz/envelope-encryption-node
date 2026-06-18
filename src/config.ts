export function mustGetenv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`FATAL: Environment variable ${name} is not set!`);
    process.exit(1);
  }
  return value;
}

export const ENCRYPTION_KEY_ID = mustGetenv("ENCRYPTION_KEY_ID");
