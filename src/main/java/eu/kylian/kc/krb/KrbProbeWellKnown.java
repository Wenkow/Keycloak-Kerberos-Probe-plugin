package eu.kylian.kc.krb;

import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.wellknown.WellKnownProvider;

import java.util.Collections;

public class KrbProbeWellKnown implements WellKnownProvider {
    private final KeycloakSession session;

    public KrbProbeWellKnown(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getConfig() {
        return Collections.emptyMap();
    }

    static boolean isHttps(HttpRequest req) {
        return "https".equalsIgnoreCase(req.getHttpHeaders().getHeaderString("X-Forwarded-Proto"));
    }

    @Override
    public void close() {
    }
}
