const message = "All your base are belong to us.";
const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
  "encrypt",
  "decrypt",
]);
const iv = crypto.getRandomValues(new Uint8Array(12));

const ciphertext = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  key,
  new TextEncoder().encode(message),
);

const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
const asString = new TextDecoder().decode(decrypted);
console.log({ asString });
