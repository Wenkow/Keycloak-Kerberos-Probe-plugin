package eu.kylian.kc.krb;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.mockito.Mockito.*;

class CookieConditionTest {

    @Test
    void passesWhenCookieOne() {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String,String> headers = new MultivaluedHashMap<>();
        headers.add("Cookie", "foo=bar; KRB_CAPABLE=1; x=y");

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);

        CookieCondition cond = new CookieCondition();
        cond.authenticate(ctx);

        verify(ctx, times(1)).success();
        verify(ctx, never()).attempted();
    }

    private AuthenticationFlowContext ctxWith(String cookie, String netNote) {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String,String> headers = new MultivaluedHashMap<>();
        headers.add("Cookie", cookie);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getAuthNote("KRB_NET_OK")).thenReturn(netNote);

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);
        when(ctx.getAuthenticationSession()).thenReturn(session);
        return ctx;
    }

    @Test
    void skipsWhenClientIsOutsideInternalNetworks() {
        AuthenticationFlowContext ctx = ctxWith("KRB_CAPABLE=1", "0");
        new CookieCondition().authenticate(ctx);

        verify(ctx).attempted();
        verify(ctx, never()).success();
    }

    @Test
    void passesWhenClientIsInsideInternalNetworks() {
        AuthenticationFlowContext ctx = ctxWith("KRB_CAPABLE=1", "1");
        new CookieCondition().authenticate(ctx);

        verify(ctx).success();
        verify(ctx, never()).attempted();
    }

    @Test
    void passesWhenNoNetworkNoteIsSet() {
        AuthenticationFlowContext ctx = ctxWith("KRB_CAPABLE=1", null);
        new CookieCondition().authenticate(ctx);

        verify(ctx).success();
    }

    @Test
    void skipsWhenMissingOrZero() {
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String,String> headers = new MultivaluedHashMap<>();
        headers.add("Cookie", "foo=bar; KRB_CAPABLE=0;");

        when(ctx.getHttpRequest()).thenReturn(req);
        when(req.getHttpHeaders()).thenReturn(httpHeaders);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);

        CookieCondition cond = new CookieCondition();
        cond.authenticate(ctx);

        verify(ctx, times(1)).attempted();
        verify(ctx, never()).success();
    }
}
