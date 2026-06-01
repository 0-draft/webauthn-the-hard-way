// Registration ceremony driver.
//
// 1. POST /register/begin -> PublicKeyCredentialCreationOptions JSON.
// 2. Convert the base64url byte fields back into ArrayBuffers (the WebAuthn API
//    expects ArrayBuffers, not strings).
// 3. Call navigator.credentials.create({publicKey: options}).
// 4. Pull clientDataJSON + attestationObject out of the response, base64url-encode
//    them, POST them to /register/complete.

const $ = (id) => document.getElementById(id);
const log = (msg, cls = "info") => {
  const pre = $("log");
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = `[${new Date().toLocaleTimeString()}] ${msg}\n`;
  pre.appendChild(span);
  pre.scrollTop = pre.scrollHeight;
};

// ---- base64url helpers ----
// WebAuthn uses base64url WITHOUT padding (per the CollectedClientData spec).
// We round-trip through plain base64 to keep this dependency-free.
function b64urlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64urlDecode(str) {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  const bin = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json;
}

$("register").addEventListener("click", async () => {
  const btn = $("register");
  btn.disabled = true;
  try {
    const username = $("username").value.trim() || "demo";
    log(`POST /register/begin (username=${username})`);
    const options = await postJSON("/register/begin", { username });
    log(`  challenge: ${options.challenge}`);
    log(`  user.id:   ${options.user.id}`);

    // Convert base64url -> ArrayBuffer for the fields the WebAuthn API requires
    // as binary.
    options.challenge = b64urlDecode(options.challenge);
    options.user.id = b64urlDecode(options.user.id);
    for (const c of options.excludeCredentials || []) c.id = b64urlDecode(c.id);

    log("navigator.credentials.create() -> waiting for authenticator...");
    const cred = await navigator.credentials.create({ publicKey: options });
    log(`  credential.id: ${cred.id}`);
    log(`  authenticatorAttachment: ${cred.authenticatorAttachment}`);

    const body = {
      clientDataJSON: b64urlEncode(cred.response.clientDataJSON),
      attestationObject: b64urlEncode(cred.response.attestationObject),
    };
    log(`POST /register/complete (clientDataJSON=${body.clientDataJSON.length}B, attestationObject=${body.attestationObject.length}B)`);
    const result = await postJSON("/register/complete", body);

    log(`OK registered. alg=${result.alg} aaguid=${result.aaguid} backupEligible=${result.backupEligible}`, "ok");
  } catch (e) {
    log(`ERROR ${e.message}`, "err");
  } finally {
    btn.disabled = false;
  }
});
