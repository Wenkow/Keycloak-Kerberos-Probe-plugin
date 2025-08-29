package eu.kylian.kc.krb;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Optional;

public class BackchannelProbeAuthenticator implements Authenticator {
    public static final String COOKIE = "KRB_CAPABLE";

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        String cookies = Optional.ofNullable(
                ctx.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("Cookie")
        ).orElse("");

        if (cookies.contains(COOKIE + "=1") || cookies.contains(COOKIE + "=0")) {
            ctx.attempted();
            return;
        }

        String realm = Optional.ofNullable(ctx.getRealm()).map(RealmModel::getName).orElse("master");
        String base = "/realms/" + realm + "/krb";

        String cfgTimeout = Optional.ofNullable(ctx.getAuthenticatorConfig())
                .map(c -> c.getConfig().get("timeoutMs")).orElse("500");
        int timeout;
        try {
            timeout = Math.max(100, Integer.parseInt(cfgTimeout));
        } catch (Exception e) {
            timeout = 500;
        }

        // Get cookie validity configuration
        String cfgCookieValidity = Optional.ofNullable(ctx.getAuthenticatorConfig())
                .map(c -> c.getConfig().get("cookieValiditySec")).orElse("1800");
        int cookieValidity;
        try {
            cookieValidity = Math.max(60, Integer.parseInt(cfgCookieValidity)); // Minimum 60 seconds
        } catch (Exception e) {
            cookieValidity = 1800;
        }

        // Store cookie validity in session for provider to access
        KeycloakSession session = ctx.getSession();
        if (session != null) {
            session.setAttribute("krb_cookie_validity", cookieValidity);
        }

        String html =
                "<!doctype html><meta charset=\"utf-8\">" +
                        "<script>(async()=>{" +
                        "let done=false;" +
                        "const go=u=>fetch(u,{credentials:'include',cache:'no-store',redirect:'manual'}).catch(()=>{});" +
                        "setTimeout(()=>{ if(!done){ go('" + base + "/mark?v=0'); location.replace(location.href);} }, " + timeout + ");" +
                        "try{ await go('" + base + "/test'); done=true; location.replace(location.href);}catch(e){}" +
                        "})();</script>";

        Response page = Response.ok(html)
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
                .type(MediaType.TEXT_HTML_TYPE)
                .build();

        ctx.forceChallenge(page);
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
