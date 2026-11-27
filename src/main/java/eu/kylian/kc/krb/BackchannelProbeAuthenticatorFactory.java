package eu.kylian.kc.krb;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class BackchannelProbeAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "krb-backchannel-probe";
    private static final BackchannelProbeAuthenticator SINGLETON = new BackchannelProbeAuthenticator();

    private static final ProviderConfigProperty TIMEOUT =
            new ProviderConfigProperty("timeoutMs",
                    "Probe timeout (ms)",
                    "If no response within this time, assume not capable and continue with form.",
                    ProviderConfigProperty.STRING_TYPE, "500");

    private static final ProviderConfigProperty COOKIE_VALIDITY =
            new ProviderConfigProperty("cookieValiditySec",
                    "Cookie validity (seconds)",
                    "How long to remember Kerberos capability (prevents repeated probes).",
                    ProviderConfigProperty.STRING_TYPE, "1800");

    private static final ProviderConfigProperty INTERNAL_NETWORKS =
            new ProviderConfigProperty(BackchannelProbeAuthenticator.NETWORKS_CONFIG,
                    "Internal networks (optional)",
                    "CIDR prefixes, IPv4 and IPv6, separated by comma or new line (e.g. 10.0.0.0/8, 192.168.0.0/16, fd00::/8). " +
                    "The probe and the Kerberos condition run only for clients from these networks. " +
                    "Leave empty to apply them to all clients.",
                    ProviderConfigProperty.TEXT_TYPE, "");

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public Authenticator create(KeycloakSession s) {
        return SINGLETON;
    }

    @Override
    public void init(org.keycloak.Config.Scope s) {
    }

    @Override
    public void postInit(KeycloakSessionFactory f) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getDisplayType() {
        return "Kerberos Backchannel Probe";
    }

    @Override
    public String getHelpText() {
        return "Probes SPNEGO via backchannel; sets KRB_CAPABLE cookie; avoids basic-auth prompts.";
    }

    @Override
    public String getReferenceCategory() {
        return "Kerberos";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(TIMEOUT, COOKIE_VALIDITY, INTERNAL_NETWORKS);
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED};
    }
}
