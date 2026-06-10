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
        int cv = getCookieValidity(ctx);
        int timeout = getTimeout(ctx);
        String probeUrl = "/realms/" + realm + "/.well-known/kerberos-probe?cv=" + cv;
        String secureAttr = KrbProbeWellKnown.isHttps(ctx.getHttpRequest()) ? ";Secure" : "";
        String cookieVal = "KRB_CAPABLE=0;path=/;max-age=" + cv + ";SameSite=Lax" + secureAttr;

        String html =
                "<!doctype html><meta charset=\"utf-8\">" +
                "<script>(async()=>{" +
                "let done=false;" +
                "const go=u=>fetch(u,{credentials:'include',cache:'no-store',redirect:'manual'}).catch(()=>{});" +
                "setTimeout(()=>{ if(!done){" +
                "document.cookie='" + cookieVal + "';" +
                "location.replace(location.href);} }," + timeout + ");" +
                "try{ const r=await go('" + probeUrl + "'); done=true;" +
                "if(!r||r.status!==200)document.cookie='" + cookieVal + "';" +
                "location.replace(location.href);}catch(e){}" +
                "})();</script>";

        ctx.forceChallenge(Response.ok(html)
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
                .type(MediaType.TEXT_HTML_TYPE)
                .build());
    }

    private int getCookieValidity(AuthenticationFlowContext ctx) {
        String raw = Optional.ofNullable(ctx.getAuthenticatorConfig())
                .map(c -> c.getConfig().get("cookieValiditySec")).orElse("1800");
        try {
            return Math.max(60, Integer.parseInt(raw));
        } catch (Exception e) {
            return 1800;
        }
    }

    private int getTimeout(AuthenticationFlowContext ctx) {
        String raw = Optional.ofNullable(ctx.getAuthenticatorConfig())
                .map(c -> c.getConfig().get("timeoutMs")).orElse("500");
        try {
            return Math.max(100, Integer.parseInt(raw));
        } catch (Exception e) {
            return 500;
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
