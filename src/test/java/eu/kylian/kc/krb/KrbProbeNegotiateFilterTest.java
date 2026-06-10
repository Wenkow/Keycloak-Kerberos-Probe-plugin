package eu.kylian.kc.krb;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KrbProbeNegotiateFilterTest {

    private static final String KERBEROS_TOKEN = "YGhpYXNoYm9keQ==";
    private static final String NTLM_TOKEN = "TlRMTVNTUAABAAAAl4II4g==";

    private ContainerRequestContext mockCtx(String path, String auth, String cvParam, String forwardedProto) {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uri = mock(UriInfo.class);
        when(ctx.getUriInfo()).thenReturn(uri);
        when(uri.getPath()).thenReturn(path);
        when(ctx.getHeaderString("Authorization")).thenReturn(auth);
        when(ctx.getHeaderString("X-Forwarded-Proto")).thenReturn(forwardedProto);
        MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
        if (cvParam != null) params.putSingle("cv", cvParam);
        when(uri.getQueryParameters()).thenReturn(params);
        return ctx;
    }

    @Test
    void skipsNonProbePaths() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/master/protocol/openid-connect/token", null, null, null);
        new KrbProbeNegotiateFilter().filter(ctx);
        verify(ctx, never()).abortWith(any());
    }

    @Test
    void returns401WithNegotiateWhenNoAuth() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/sitmp/.well-known/kerberos-probe", null, null, null);
        new KrbProbeNegotiateFilter().filter(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(cap.capture());
        Response r = cap.getValue();
        assertEquals(401, r.getStatus());
        assertEquals("Negotiate", r.getHeaderString("WWW-Authenticate"));
        assertEquals("0", r.getCookies().get(BackchannelProbeAuthenticator.COOKIE).getValue());
    }

    @Test
    void returns200WithCookieOneOnKerberos() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/sitmp/.well-known/kerberos-probe",
                "Negotiate " + KERBEROS_TOKEN, null, null);
        new KrbProbeNegotiateFilter().filter(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(cap.capture());
        Response r = cap.getValue();
        assertEquals(200, r.getStatus());
        assertEquals("1", r.getCookies().get(BackchannelProbeAuthenticator.COOKIE).getValue());
    }

    @Test
    void returns200WithCookieZeroOnNtlm() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/sitmp/.well-known/kerberos-probe",
                "Negotiate " + NTLM_TOKEN, null, null);
        new KrbProbeNegotiateFilter().filter(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(cap.capture());
        assertEquals("0", cap.getValue().getCookies().get(BackchannelProbeAuthenticator.COOKIE).getValue());
    }

    @Test
    void usesCvQueryParamForCookieMaxAge() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/sitmp/.well-known/kerberos-probe",
                "Negotiate " + KERBEROS_TOKEN, "3600", null);
        new KrbProbeNegotiateFilter().filter(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(cap.capture());
        assertEquals(3600, cap.getValue().getCookies().get(BackchannelProbeAuthenticator.COOKIE).getMaxAge());
    }

    @Test
    void cookieSecureWhenHttps() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/sitmp/.well-known/kerberos-probe",
                "Negotiate " + KERBEROS_TOKEN, null, "https");
        new KrbProbeNegotiateFilter().filter(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(cap.capture());
        assertTrue(cap.getValue().getCookies().get(BackchannelProbeAuthenticator.COOKIE).isSecure());
    }

    @Test
    void cookieNotSecureWhenHttp() throws IOException {
        ContainerRequestContext ctx = mockCtx("/realms/sitmp/.well-known/kerberos-probe",
                "Negotiate " + KERBEROS_TOKEN, null, "http");
        new KrbProbeNegotiateFilter().filter(ctx);

        ArgumentCaptor<Response> cap = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(cap.capture());
        assertFalse(cap.getValue().getCookies().get(BackchannelProbeAuthenticator.COOKIE).isSecure());
    }

    @Test
    void parseCvDefaultsTo1800WhenAbsent() {
        MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
        assertEquals(1800, KrbProbeNegotiateFilter.parseCv(params));
    }

    @Test
    void parseCvClampsToMinimum60() {
        MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("cv", "10");
        assertEquals(60, KrbProbeNegotiateFilter.parseCv(params));
    }
}
