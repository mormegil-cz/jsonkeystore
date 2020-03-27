package cz.mormegil.jsonkeystore;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Information about the version of the jsonkeystore library.
 */
public final class VersionInfo {
    /**
     * Version number of the library
     */
    public static final String VERSION_NUMBER;

    static {
        final Properties versionInfoProperties = new Properties();
        try {
            try (final InputStream stream = VersionInfo.class.getClassLoader().getResourceAsStream("jsonkeystoreversion.properties")) {
                if (stream != null) {
                    versionInfoProperties.load(stream);
                }
            }
        } catch (IOException e) {
            // ignore, just do not load anything
        }
        VERSION_NUMBER = versionInfoProperties.getProperty("VERSION");
    }

    private VersionInfo() {
    }
}
