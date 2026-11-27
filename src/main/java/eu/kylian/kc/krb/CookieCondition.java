package eu.kylian.kc.krb;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Optional;

public class CookieCondition implements Authenticator {
    public static final String COOKIE = "KRB_CAPABLE";

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        String c = Optional.ofNullable(
                ctx.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("Cookie")
        ).orElse("");
        // The probe step records whether the client is in an internal network. A cookie from an earlier
        // visit inside the network must not trigger Kerberos from outside it.
        AuthenticationSessionModel session = ctx.getAuthenticationSession();
        boolean outsideNetworks = session != null
                && "0".equals(session.getAuthNote(BackchannelProbeAuthenticator.NET_NOTE));
        if (c.contains(COOKIE + "=1") && !outsideNetworks) {
            ctx.success();
        } else {
            ctx.attempted();
        }
    }

    @Override
    public void action(AuthenticationFlowContext ctx) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {
    }

    @Override
    public void close() {
    }
}
