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
        return Collections.singletonList(TIMEOUT);
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED};
    }
}
