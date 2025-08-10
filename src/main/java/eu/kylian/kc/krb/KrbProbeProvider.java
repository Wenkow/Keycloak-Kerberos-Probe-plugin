package eu.kylian.kc.krb;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Optional;

@Path("/")
public class KrbProbeProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public KrbProbeProvider(KeycloakSession session) {
        this.session = session;
    }

    public static final String COOKIE = "KRB_CAPABLE";
    private static final String NTLM1 = "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw==";

    @GET
    @Path("test")
    public Response test(@jakarta.ws.rs.core.Context HttpHeaders headers) {
        String a = Optional.ofNullable(headers.getHeaderString("Authorization")).orElse("");
        NewCookie c0 = new NewCookie(COOKIE, "0", "/", null, null, 1800, true, true);

        boolean negotiate = a.regionMatches(true, 0, "Negotiate ", 0, 10);
        if (negotiate && !a.equals(NTLM1)) {
            NewCookie c1 = new NewCookie(COOKIE, "1", "/", null, null, 1800, true, true);
            return Response.ok("OK").cookie(c1).build();
        }
        return Response.status(401)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Negotiate")
                .cookie(c0)
                .build();
    }

    @GET
    @Path("mark")
    public Response mark(@jakarta.ws.rs.QueryParam("v") String v) {
        String val = "1".equals(v) ? "1" : "0";
        NewCookie c = new NewCookie(COOKIE, val, "/", null, null, 1800, true, true);
        return Response.noContent().cookie(c).build();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }
}
