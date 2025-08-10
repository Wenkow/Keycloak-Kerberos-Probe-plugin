package eu.kylian.kc.krb;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Optional;

public class CookieCondition implements Authenticator {
    public static final String COOKIE = "KRB_CAPABLE";

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        String c = Optional.ofNullable(
                ctx.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("Cookie")
        ).orElse("");
        if (c.contains(COOKIE + "=1")) {
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
