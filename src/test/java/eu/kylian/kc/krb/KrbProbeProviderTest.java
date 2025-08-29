package eu.kylian.kc.krb;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KrbProbeProviderTest {

    @Test
    void returns401AndSetsZeroCookieWhenNoAuth() {
        KrbProbeProvider p = new KrbProbeProvider(null);
        HttpHeaders hdrs = mock(HttpHeaders.class);
        when(hdrs.getHeaderString("Authorization")).thenReturn(null);

        Response r = p.test(hdrs);
        assertEquals(401, r.getStatus());
        assertTrue(r.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE).toString().contains("Negotiate"));
        assertTrue(r.getCookies().containsKey("KRB_CAPABLE"));
        assertEquals("0", r.getCookies().get("KRB_CAPABLE").getValue());
    }

    @Test
    void returns401AndZeroCookieOnNtlmType1() {
        String ntlm = "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw==";
        KrbProbeProvider p = new KrbProbeProvider(null);
        HttpHeaders hdrs = mock(HttpHeaders.class);
        when(hdrs.getHeaderString("Authorization")).thenReturn(ntlm);

        Response r = p.test(hdrs);
        assertEquals(401, r.getStatus());
        assertEquals("0", r.getCookies().get("KRB_CAPABLE").getValue());
    }

    @Test
    void returns200AndOneCookieOnNegotiateToken() {
        String token = "Negotiate YGhpYXNoYm9keQ==";
        KrbProbeProvider p = new KrbProbeProvider(null);
        HttpHeaders hdrs = mock(HttpHeaders.class);
        when(hdrs.getHeaderString("Authorization")).thenReturn(token);

        Response r = p.test(hdrs);
        assertEquals(200, r.getStatus());
        assertEquals("1", r.getCookies().get("KRB_CAPABLE").getValue());
    }

    @Test
    void usesDefaultCookieValidityWhenNoSession() {
        KrbProbeProvider p = new KrbProbeProvider(null);
        HttpHeaders hdrs = mock(HttpHeaders.class);
        when(hdrs.getHeaderString("Authorization")).thenReturn(null);

        Response r = p.test(hdrs);
        NewCookie cookie = r.getCookies().get("KRB_CAPABLE");
        assertEquals(1800, cookie.getMaxAge()); // Default value
    }

    @Test
    void usesCustomCookieValidityFromSession() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute("krb_cookie_validity")).thenReturn(3600);
        
        KrbProbeProvider p = new KrbProbeProvider(session);
        HttpHeaders hdrs = mock(HttpHeaders.class);
        when(hdrs.getHeaderString("Authorization")).thenReturn(null);

        Response r = p.test(hdrs);
        NewCookie cookie = r.getCookies().get("KRB_CAPABLE");
        assertEquals(3600, cookie.getMaxAge()); // Custom value from session
    }

    @Test
    void handlesInvalidSessionAttributeGracefully() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute("krb_cookie_validity")).thenReturn("invalid");
        
        KrbProbeProvider p = new KrbProbeProvider(session);
        HttpHeaders hdrs = mock(HttpHeaders.class);
        when(hdrs.getHeaderString("Authorization")).thenReturn(null);

        Response r = p.test(hdrs);
        NewCookie cookie = r.getCookies().get("KRB_CAPABLE");
        assertEquals(1800, cookie.getMaxAge()); // Should fall back to default
    }

    @Test
    void markEndpointUsesCustomCookieValidity() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute("krb_cookie_validity")).thenReturn(7200);
        
        KrbProbeProvider p = new KrbProbeProvider(session);

        Response r = p.mark("0");
        assertEquals(204, r.getStatus());
        NewCookie cookie = r.getCookies().get("KRB_CAPABLE");
        assertEquals("0", cookie.getValue());
        assertEquals(7200, cookie.getMaxAge()); // Custom value from session
    }
}
