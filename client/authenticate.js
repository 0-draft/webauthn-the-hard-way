// Authentication ceremony driver.
//
// 1. POST /authenticate/begin -> PublicKeyCredentialRequestOptions JSON.
// 2. Convert base64url byte fields -> ArrayBuffers.
// 3. Call navigator.credentials.get({publicKey: options}).
// 4. Extract clientDataJSON + authenticatorData + signature, POST them to
//    /authenticate/complete along with the credentialId the authenticator chose.

$("authenticate").addEventListener("click", async () => {
  const btn = $("authenticate");
  btn.disabled = true;
  try {
    log("POST /authenticate/begin");
    const options = await postJSON("/authenticate/begin", {});
    log(`  challenge: ${options.challenge}`);
    log(`  allowCredentials: ${options.allowCredentials.length}`);

    options.challenge = b64urlDecode(options.challenge);
    for (const c of options.allowCredentials || []) c.id = b64urlDecode(c.id);

    log("navigator.credentials.get() -> waiting for authenticator...");
    const cred = await navigator.credentials.get({ publicKey: options });
    log(`  credential.id: ${cred.id}`);

    const body = {
      credentialId: cred.id, // already base64url
      clientDataJSON: b64urlEncode(cred.response.clientDataJSON),
      authenticatorData: b64urlEncode(cred.response.authenticatorData),
      signature: b64urlEncode(cred.response.signature),
    };
    log(`POST /authenticate/complete (signature=${body.signature.length}B)`);
    const result = await postJSON("/authenticate/complete", body);

    log(`OK authenticated. userHandle=${result.userHandle} newSignCount=${result.newSignCount} backupState=${result.backupState}`, "ok");
  } catch (e) {
    log(`ERROR ${e.message}`, "err");
  } finally {
    btn.disabled = false;
  }
});

$("list").addEventListener("click", async () => {
  try {
    const res = await fetch("/credentials");
    const creds = await res.json();
    log(`Stored credentials (${creds.length}):`);
    for (const c of creds) {
      log(`  id=${c.credentialId.slice(0, 16)}... aaguid=${c.aaguid} signCount=${c.signCount}`);
    }
  } catch (e) {
    log(`ERROR ${e.message}`, "err");
  }
});

$("reset").addEventListener("click", async () => {
  try {
    await postJSON("/credentials/reset", {});
    log("Credential store reset.", "ok");
  } catch (e) {
    log(`ERROR ${e.message}`, "err");
  }
});
