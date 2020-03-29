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

    /**
     * Version number of the library represented as a floating-point number
     */
    public static final double VERSION_NUMBER_FLOAT;

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
        final String versionStr = versionInfoProperties.getProperty("VERSION");
        VERSION_NUMBER = versionStr;
        VERSION_NUMBER_FLOAT = parseVersionStr(versionStr);
    }

    private static double parseVersionStr(String versionStr) {
        if (versionStr == null) {
            return 0d;
        }
        try {
            int firstDotIdx = versionStr.indexOf('.');
            int nextDotIdx = versionStr.indexOf('.', firstDotIdx + 1);
            if (nextDotIdx != -1) {
                versionStr = versionStr.substring(0, nextDotIdx);
            }
            return Double.parseDouble(versionStr);
        } catch (NullPointerException | NumberFormatException e) {
            return 0d;
        }
    }

    private VersionInfo() {
    }
}
