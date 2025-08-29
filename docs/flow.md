## Plugin diagram  

Actors:  
  BROWSER (incognito or normal)  
  KEYCLOAK (realm = {R})  

Flow (top-level Browser flow):  
  Cookie (ALT)  
  Kerberos Backchannel Probe (ALT)  ← returns tiny page with inline JS below  
  Kerberos Path (ALT)  
    - Condition: KRB_CAPABLE cookie (REQ)  
    - Kerberos (REQ)  
  Username Password Form (ALT/REQ)  
  
=====================================================================  


1) Initial auth navigation
---------------------------------------------------------------------  
BROWSER  -> KEYCLOAK:  GET /realms/{R}/login-actions/authenticate?...  (no SPNEGO yet)  
KEYCLOAK -> BROWSER :  200 OK  (HTML with inline JS to probe)  
  
Inline JS (simplified):  

  let done=false;  
  const probe = () => fetch('/realms/{R}/krb/test', {  
    credentials:'include', cache:'no-store', redirect:'manual'  
  }).then(r => { done=true; location.replace(location.href); });  
  
  setTimeout(() => { if(!done){  
    fetch('/realms/{R}/krb/mark?v=0', {credentials:'include'}).finally(() =>   location.replace(location.href));  
  }}, <timeoutMs=500>);  
  
  probe();  
  
2) Backchannel probe (Kerberos-capable browser path)
-----------------------------------------------------------
BROWSER  -> KEYCLOAK:  GET /realms/{R}/krb/test  
KEYCLOAK -> BROWSER :  401 Unauthorized  
                      WWW-Authenticate: Negotiate  
                      Set-Cookie: KRB_CAPABLE=0; Path=/; SameSite=None; Secure  

BROWSER  -> KEYCLOAK:  GET /realms/{R}/krb/test  
                        Authorization: Negotiate <SPNEGO-token>  
KEYCLOAK -> BROWSER :  200 OK  
                      Set-Cookie: ```KRB_CAPABLE=1; Path=/; SameSite=None; Secure```  
  
BROWSER  -> KEYCLOAK:  GET (reload original /login-actions/authenticate?... )  
[Flow sees ```KRB_CAPABLE=1```] → enters "Kerberos Path" subflow  
  Condition passes → Kerberos (SPNEGO) → user authenticated  
KEYCLOAK -> BROWSER :  302/200 (continues normal SSO)  

3) Backchannel probe (non-capable / incognito timeout path)
-----------------------------------------------------------

BROWSER  :  Timer fires before probe completes (e.g., 500ms)  
BROWSER  -> KEYCLOAK:  GET /realms/{R}/krb/mark?v=0  
KEYCLOAK -> BROWSER :  204 No Content  
BROWSER  :  Reloads original /login-actions/authenticate?...   
[Flow sees ```KRB_CAPABLE=0```] → "Kerberos Path" subflow is skipped  
→ falls through to Username Password Form (no SPNEGO pop-up)  
  
  
Cookie semantics:  

```KRB_CAPABLE=1```  → client proved SPNEGO works (via /krb/test 200)  
```KRB_CAPABLE=0```  → client timed out or returned NTLM Type 1 / no token  
  (Short TTL ~30 min; probe is not re-run while cookie present)  
