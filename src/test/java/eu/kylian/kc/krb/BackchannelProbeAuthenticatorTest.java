package eu.kylian.kc.krb;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BackchannelProbeAuthenticatorTest {

    private AuthenticationFlowContext mockCtx(String cookieHeader) {
        return mockCtx(cookieHeader, null);
    }

    private AuthenticationFlowContext mockCtx(String cookieHeader, String forwardedProto) {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        RealmModel realm = mock(RealmModel.class);

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(ctx.getRealm()).thenReturn(realm);
        when(realm.getName()).thenReturn("master");
        when(httpHeaders.getHeaderString("X-Forwarded-Proto")).thenReturn(forwardedProto);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        if (cookieHeader != null) {
            headers.putSingle("Cookie", cookieHeader);
        }
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);

        return ctx;
    }

    @Test
    void attemptsWhenCookieOnePresent() {
        AuthenticationFlowContext ctx = mockCtx("KRB_CAPABLE=1");
        new BackchannelProbeAuthenticator().authenticate(ctx);
        verify(ctx).attempted();
        verify(ctx, never()).forceChallenge(any());
    }

    @Test
    void attemptsWhenCookieZeroPresent() {
        AuthenticationFlowContext ctx = mockCtx("KRB_CAPABLE=0");
        new BackchannelProbeAuthenticator().authenticate(ctx);
        verify(ctx).attempted();
        verify(ctx, never()).forceChallenge(any());
    }

    @Test
    void servesProbeHtmlWhenNoCookie() {
        AuthenticationFlowContext ctx = mockCtx(null);
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        assertEquals(200, cap.getValue().getStatus());
        assertTrue(cap.getValue().getMediaType().toString().startsWith("text/html"));
        verify(ctx, never()).attempted();
    }

    @Test
    void probeHtmlContainsWellKnownUrl() {
        AuthenticationFlowContext ctx = mockCtx(null);
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        assertTrue(body.contains("/.well-known/kerberos-probe"), "HTML must fetch the well-known probe URL");
        assertTrue(body.contains("location.replace"), "HTML must reload after probe");
    }

    @Test
    void probeHtmlContainsDefaultCookieValidity() {
        AuthenticationFlowContext ctx = mockCtx(null);
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        assertTrue(body.contains("cv=1800"), "HTML must include default cv=1800 in probe URL");
    }

    @Test
    void probeHtmlSetsCookieZeroOnTimeout() {
        AuthenticationFlowContext ctx = mockCtx(null);
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        assertTrue(body.contains("KRB_CAPABLE=0"), "Timeout handler must set KRB_CAPABLE=0");
        assertTrue(body.contains("max-age=1800"), "Timeout cookie must use default max-age");
    }

    @Test
    void probeHtmlSetsCookieZeroOnNon200Response() {
        AuthenticationFlowContext ctx = mockCtx(null);
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        // JS must set cookie=0 when probe returns non-200 (e.g. 404 if provider not registered)
        assertTrue(body.contains("r.status!==200") || body.contains("r.status !== 200"),
                "JS must set KRB_CAPABLE=0 cookie when probe response is not 200");
    }

    @Test
    void probeHtmlCookieHasSecureAttrWhenHttps() {
        AuthenticationFlowContext ctx = mockCtx(null, "https");
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        assertTrue(body.contains(";Secure"), "JS cookie must include ;Secure when X-Forwarded-Proto is https");
    }

    @Test
    void probeHtmlCookieHasNoSecureAttrWhenHttp() {
        AuthenticationFlowContext ctx = mockCtx(null, "http");
        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        assertFalse(body.contains(";Secure"), "JS cookie must not include ;Secure when X-Forwarded-Proto is http");
    }

    @Test
    void customCookieValidityPassedToProbeUrl() {
        AuthenticationFlowContext ctx = mockCtx(null);
        AuthenticatorConfigModel cfg = mock(AuthenticatorConfigModel.class);
        when(cfg.getConfig()).thenReturn(Map.of("cookieValiditySec", "3600"));
        when(ctx.getAuthenticatorConfig()).thenReturn(cfg);

        new BackchannelProbeAuthenticator().authenticate(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).forceChallenge(cap.capture());
        String body = (String) cap.getValue().getEntity();
        assertTrue(body.contains("cv=3600"));
        assertTrue(body.contains("max-age=3600"));
    }
}
