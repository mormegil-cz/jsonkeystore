package cz.mormegil.jsonkeystore;

import java.security.InvalidParameterException;
import java.security.Provider;
import java.security.Security;

public class JsonKeyStoreProvider extends Provider {
    public JsonKeyStoreProvider() {
        super("JsonKeyStoreProvider", VersionInfo.VERSION_NUMBER,
                "A provider of a simple portable format for keystores called JSONKS");
        putService(new JsonKeyStoreProviderService(this));
    }

    public static void ensureRegistered() {
        if (Security.getProvider("JsonKeyStoreProvider") == null) {
            Security.addProvider(new JsonKeyStoreProvider());
        }
    }

    private static final class JsonKeyStoreProviderService extends Provider.Service {
        JsonKeyStoreProviderService(Provider provider) {
            super(provider, "KeyStore", "JSONKS", JsonKeyStore.class.getName(), null, null);
        }

        @Override
        public Object newInstance(Object constructorParameter) {
            if (constructorParameter != null) {
                throw new InvalidParameterException("No constructor parameters expected for this class");
            }
            return new JsonKeyStore();
        }
    }
}
