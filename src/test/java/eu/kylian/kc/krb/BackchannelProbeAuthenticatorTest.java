package eu.kylian.kc.krb;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BackchannelProbeAuthenticatorTest {

    @Test
    void attemptsWhenCookiePresent() {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String,String> headers = new MultivaluedHashMap<>();
        headers.add("Cookie", "KRB_CAPABLE=1");

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);

        BackchannelProbeAuthenticator a = new BackchannelProbeAuthenticator();
        a.authenticate(ctx);

        verify(ctx, times(1)).attempted();
        verify(ctx, never()).forceChallenge(any());
    }

    @Test
    void challengesWhenCookieMissing() {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String,String> headers = new MultivaluedHashMap<>();

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);

        BackchannelProbeAuthenticator a = new BackchannelProbeAuthenticator();
        a.authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx, times(1)).forceChallenge(cap.capture());
        Response r = cap.getValue();
        assertEquals("text/html", r.getMediaType().toString());
        assertTrue(r.getEntity().toString().contains("/krb/test"));
    }

    @Test
    void setsCookieValidityInSession() {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        KeycloakSession session = mock(KeycloakSession.class);
        MultivaluedMap<String,String> headers = new MultivaluedHashMap<>();

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);
        when(ctx.getSession()).thenReturn(session);
        when(ctx.getAuthenticatorConfig()).thenReturn(null); // No config, should use default

        BackchannelProbeAuthenticator a = new BackchannelProbeAuthenticator();
        a.authenticate(ctx);

        // Verify that the session attribute is set with the default value
        verify(session, times(1)).setAttribute("krb_cookie_validity", 1800);
    }
}
