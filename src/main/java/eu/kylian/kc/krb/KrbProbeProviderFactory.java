package eu.kylian.kc.krb;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class KrbProbeProviderFactory implements RealmResourceProviderFactory {
    public static final String ID = "krb";

    @Override
    public RealmResourceProvider create(KeycloakSession s) {
        return new KrbProbeProvider(s);
    }

    @Override
    public void init(org.keycloak.Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory f) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
