package eu.kylian.kc.krb;

import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KrbProbeWellKnownTest {

    @Test
    void getConfigReturnsEmptyMap() {
        KeycloakSession session = mock(KeycloakSession.class);
        assertEquals(Collections.emptyMap(), new KrbProbeWellKnown(session).getConfig());
    }

    @Test
    void isHttpsReturnsTrueWhenHeaderIsHttps() {
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        when(req.getHttpHeaders()).thenReturn(headers);
        when(headers.getHeaderString("X-Forwarded-Proto")).thenReturn("https");
        assertTrue(KrbProbeWellKnown.isHttps(req));
    }

    @Test
    void isHttpsReturnsFalseWhenHeaderIsHttp() {
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        when(req.getHttpHeaders()).thenReturn(headers);
        when(headers.getHeaderString("X-Forwarded-Proto")).thenReturn("http");
        assertFalse(KrbProbeWellKnown.isHttps(req));
    }

    @Test
    void isHttpsReturnsFalseWhenHeaderAbsent() {
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        when(req.getHttpHeaders()).thenReturn(headers);
        when(headers.getHeaderString("X-Forwarded-Proto")).thenReturn(null);
        assertFalse(KrbProbeWellKnown.isHttps(req));
    }
}
