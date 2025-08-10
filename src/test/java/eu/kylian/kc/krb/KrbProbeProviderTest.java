package eu.kylian.kc.krb;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

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
}
