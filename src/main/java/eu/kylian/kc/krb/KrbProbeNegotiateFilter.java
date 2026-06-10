package eu.kylian.kc.krb;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;

@ApplicationScoped
@Provider
@Priority(500)
public class KrbProbeNegotiateFilter implements ContainerRequestFilter {
    private static final String NTLM_PREFIX = "TlRM";

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!requestContext.getUriInfo().getPath().endsWith("kerberos-probe")) return;

        String auth = requestContext.getHeaderString("Authorization");
        int cv = parseCv(requestContext.getUriInfo().getQueryParameters());
        boolean secure = "https".equalsIgnoreCase(requestContext.getHeaderString("X-Forwarded-Proto"));

        if (auth != null && auth.regionMatches(true, 0, "Negotiate ", 0, 10)) {
            String token = auth.substring(10);
            String capable = token.startsWith(NTLM_PREFIX) ? "0" : "1";
            NewCookie cookie = new NewCookie(BackchannelProbeAuthenticator.COOKIE, capable,
                    "/", null, null, cv, secure, false);
            requestContext.abortWith(Response.ok().cookie(cookie).build());
        } else {
            NewCookie cookieZero = new NewCookie(BackchannelProbeAuthenticator.COOKIE, "0",
                    "/", null, null, cv, secure, false);
            requestContext.abortWith(
                    Response.status(401)
                            .header("WWW-Authenticate", "Negotiate")
                            .cookie(cookieZero)
                            .build()
            );
        }
    }

    static int parseCv(MultivaluedMap<String, String> params) {
        String raw = params.getFirst("cv");
        if (raw != null) {
            try { return Math.max(60, Integer.parseInt(raw)); } catch (NumberFormatException ignored) {}
        }
        return 1800;
    }
}
