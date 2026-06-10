# Changelog

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
