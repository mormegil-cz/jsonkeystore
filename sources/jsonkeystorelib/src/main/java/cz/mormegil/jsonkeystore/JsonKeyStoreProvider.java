package cz.mormegil.jsonkeystore;

import java.security.InvalidParameterException;
import java.security.Provider;
import java.security.Security;

/**
 * JCA provider implementation offering the JSONKS keystore format.
 *
 * @see JsonKeyStore
 */
public class JsonKeyStoreProvider extends Provider {
    /**
     * Constructor
     */
    //Warning suppression: We need to be backward compatible, the better API is @since 9
    @SuppressWarnings("deprecation")
    public JsonKeyStoreProvider() {
        super("JsonKeyStoreProvider", VersionInfo.VERSION_NUMBER_FLOAT,
                "A provider of a simple portable format for keystores called JSONKS");
        putService(new JsonKeyStoreProviderService(this));
    }

    /**
     * Ensure that this provider is registered as the JCA security provider in the current runtime.
     *
     * @see Security#addProvider(Provider)
     */
    public static void ensureRegistered() {
        if (Security.getProvider("JsonKeyStoreProvider") == null) {
            Security.addProvider(new JsonKeyStoreProvider());
        }
    }

    private static final class JsonKeyStoreProviderService extends Provider.Service {
        JsonKeyStoreProviderService(Provider provider) {
            super(provider, "KeyStore", "JSONKS", JsonKeyStore.class.getName(), null, null);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Object newInstance(Object constructorParameter) {
            if (constructorParameter != null) {
                throw new InvalidParameterException("No constructor parameters expected for this class");
            }
            return new JsonKeyStore();
        }
    }
}
