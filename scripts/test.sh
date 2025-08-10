#!/bin/sh

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm -v "$ROOT":/src -w /src maven:3.9-eclipse-temurin-17 mvn -B clean test
