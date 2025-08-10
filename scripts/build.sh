#!/bin/sh

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm -v "$ROOT":/src -w /src maven:3.9-eclipse-temurin-17 mvn -B clean package
test -f "$ROOT/target/keycloak-krb-probe.jar"
echo "target/keycloak-krb-probe.jar ready"
