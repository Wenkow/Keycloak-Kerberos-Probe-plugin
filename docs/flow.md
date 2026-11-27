## Plugin diagram

Actors:
  BROWSER (incognito or normal)
  KEYCLOAK (realm = {R})

Flow (top-level Browser flow):
  Cookie (ALT)
  Kerberos Backchannel Probe (ALT)  ← checks the client network, then returns a tiny page with inline JS
  Kerberos Path (ALT)
    - Condition: KRB_CAPABLE cookie (REQ)
    - Kerberos (REQ)
  Username Password Form (ALT/REQ)

=====================================================================


1) Initial auth navigation
---------------------------------------------------------------------
BROWSER  -> KEYCLOAK:  GET /realms/{R}/login-actions/authenticate?...  (no SPNEGO yet)

The probe authenticator decides what happens next:

  a) "Internal networks" is set and the client IP is outside it
     -> auth note KRB_NET_OK=0, no probe, no cookie, flow continues to the login form.
  b) KRB_CAPABLE cookie (=0 or =1) is already present
     -> probe skipped, flow continues (the condition below reads the cookie).
  c) otherwise
     -> 200 OK with an HTML page that runs the probe.

When "Internal networks" is set and the client IP is inside it, the note is KRB_NET_OK=1 and the
flow goes on with b) or c). When the field is empty, no note is set and every client takes b) or c).

Inline JS (simplified):

  const ac = new AbortController();
  const fin = bad => {                       // runs once
    if (bad) document.cookie = 'KRB_CAPABLE=0; ...';
    ac.abort();                              // cancel the pending probe request
    location.replace(location.href);
  };
  setTimeout(() => fin(true), <timeoutMs=500>);
  fetch('/realms/{R}/.well-known/kerberos-probe?cv=<cookieValiditySec>', {
    credentials:'include', cache:'no-store', redirect:'manual', signal: ac.signal
  }).then(r => fin(!r || r.status !== 200));

2) Backchannel probe (Kerberos-capable browser path)
-----------------------------------------------------------
BROWSER  -> KEYCLOAK:  GET /realms/{R}/.well-known/kerberos-probe?cv=1800
KEYCLOAK -> BROWSER :  401 Unauthorized
                      WWW-Authenticate: Negotiate
                      Set-Cookie: KRB_CAPABLE=0; Path=/; Max-Age=1800

BROWSER  -> KEYCLOAK:  GET /realms/{R}/.well-known/kerberos-probe?cv=1800
                        Authorization: Negotiate <SPNEGO-token>
KEYCLOAK -> BROWSER :  200 OK
                      Set-Cookie: KRB_CAPABLE=1; Path=/; Max-Age=1800
                      (an NTLM token, base64 prefix "TlRM", gives KRB_CAPABLE=0)

BROWSER  -> KEYCLOAK:  GET (reload original /login-actions/authenticate?...)
[Probe step sees the cookie and moves on]
[Condition sees KRB_CAPABLE=1 and KRB_NET_OK is not 0] → enters "Kerberos Path" subflow
  Condition passes → Kerberos (SPNEGO) → user authenticated
KEYCLOAK -> BROWSER :  302/200 (continues normal SSO)

The endpoint is served by a WellKnownProvider and handled in a ContainerRequestFilter. Keycloak 26.6+
rejects Negotiate headers on realm resource endpoints, which is why the probe does not live there.

3) Backchannel probe (non-capable / incognito timeout path)
-----------------------------------------------------------

BROWSER  :  Timer fires before the probe completes (e.g., 500ms)
BROWSER  :  sets KRB_CAPABLE=0, aborts the pending request, reloads /login-actions/authenticate?...
[Condition sees KRB_CAPABLE=0] → "Kerberos Path" subflow is skipped
→ falls through to Username Password Form (no SPNEGO challenge from the flow)

4) Client outside "Internal networks"
-----------------------------------------------------------
BROWSER  -> KEYCLOAK:  GET /realms/{R}/login-actions/authenticate?...
KEYCLOAK :  client IP not in the list → auth note KRB_NET_OK=0, probe step returns "attempted"
[Condition sees KRB_NET_OK=0, ignores any KRB_CAPABLE=1 cookie] → "Kerberos Path" is skipped
KEYCLOAK -> BROWSER :  200 OK, login form. No 401 Negotiate is sent, so no browser dialog appears.

The client IP comes from ClientConnection.getRemoteAddr(). Behind a proxy, enable proxy headers
(for example KC_PROXY_HEADERS=xforwarded) so Keycloak sees the real address.


Cookie semantics:

KRB_CAPABLE=1  → client proved SPNEGO works (probe endpoint returned 200 with a Kerberos token)
KRB_CAPABLE=0  → client timed out, returned an NTLM token, or sent no token
  (TTL = cookieValiditySec, default 30 min; the probe is not re-run while the cookie is present)

Auth session note KRB_NET_OK:

1      → client is inside "Internal networks"
0      → client is outside, Kerberos is off for this login
absent → "Internal networks" is empty, or the probe is not in the flow; only the cookie decides
