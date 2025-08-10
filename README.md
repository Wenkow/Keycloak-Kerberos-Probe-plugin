# Keycloak Kerberos Backchannel Probe

Avoid SPNEGO/basic-auth pop-ups in private/incognito windows by probing Kerberos on a backchannel with a timeout fallback.

## Build & Test
```bash
./scripts/test.sh
./scripts/build.sh   # => target/keycloak-krb-probe.jar
```

## Run locally (Keycloak 26)
```bash
docker run --rm -it -p 8080:8080   -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin   -v "$PWD/target/keycloak-krb-probe.jar:/opt/keycloak/providers/keycloak-krb-probe.jar"   quay.io/keycloak/keycloak:26.0.0 start-dev --auto-build
```
