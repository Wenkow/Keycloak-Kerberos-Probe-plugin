package eu.kylian.kc.krb;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;

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
