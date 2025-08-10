package eu.kylian.kc.krb;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class CookieConditionFactory implements AuthenticatorFactory {
    public static final String ID = "krb-cookie-condition";
    private static final CookieCondition SINGLETON = new CookieCondition();

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
        return "Condition - Kerberos Capable Cookie";
    }

    @Override
    public String getHelpText() {
        return "Pass if KRB_CAPABLE=1 cookie is present; otherwise skip (attempted).";
    }

    @Override
    public String getReferenceCategory() {
        return "Kerberos";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList();
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED};
    }
}
