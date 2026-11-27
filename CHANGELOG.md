# Changelog

## [1.3.0] - 2026-11-27

### Added

- Optional `Internal networks` setting on the probe execution: a list of IPv4/IPv6 CIDR prefixes.
  Clients outside the list get no probe and no `KRB_CAPABLE` cookie, so they never receive a
  `401 Negotiate` challenge and never see the native Windows credential dialog. Empty (the default)
  keeps the old behavior for all clients.
- `Condition - KRB_CAPABLE` also honors the list. The probe stores the network result in the
  authentication session, so a `KRB_CAPABLE=1` cookie from an earlier visit inside the network
  does not trigger Kerberos from outside. Without the probe in the same flow the condition only
  checks the cookie, as before.
- Invalid entries are logged and skipped. A non-empty list with no valid entry matches no client.

## [1.2.1] - 2026-11-24

### Fixed

- Microsoft Edge left the native Windows Security credential dialog open after the
  redirect to the login form when the client had no Kerberos ticket. The probe `fetch` is
  now bound to an `AbortController` and aborted before every `location.replace`, which
  cancels the pending request and closes the dialog.

## [1.2.0] - 2026-06-10

### Changed

**Probe endpoint changed to `/.well-known/kerberos-probe`; compatible with Keycloak 26.6.x**

Keycloak 26.6.x introduced a bearer token check in `resolveRealmExtension()` that breaks any
`RealmResourceProvider` endpoint when the browser sends `Authorization: Negotiate <token>`.

The probe is now served at `/.well-known/kerberos-probe` via the `WellKnownProvider` SPI,
which is not subject to this check. A `ContainerRequestFilter` (`KrbProbeNegotiateFilter`)
handles all probe auth logic via `requestContext.abortWith()`, ensuring `WWW-Authenticate`
and `Set-Cookie` response headers reach the browser intact.

Compatible with Keycloak 26.0.0 and later.

### Added

- `CookieCondition` authenticator: flow condition that checks the `KRB_CAPABLE` cookie value.

### Fixed

- Cookie validity passed from authenticator to probe endpoint via `cv=` query parameter.
- NTLM detection uses base64 prefix check (`TlRM`) covering all NTLM message types.
- `Secure` cookie flag set dynamically from `X-Forwarded-Proto: https` header.
- Probe JS sets `KRB_CAPABLE=0` on non-200 response (prevents loop if provider absent).

## [1.1.0] - 2024-11-01

Added configurable cookie lifespan.

## [1.0.0] - 2024-10-01

Initial public release.
