package cz.mormegil.jsonkeystore.tools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collections;

/**
 * A simple tool to copy/convert a keystore
 */
public class KeyStoreConvertor {
    /**
     * Copy/convert a keystore
     *
     * @param inputFile     File containing the input keystore
     * @param inputFormat   Format of the input keystore (e.g. JCEKS)
     * @param outputFile    Where should the copy be created
     * @param outputFormat  Format of the output (e.g. JSONKS)
     * @param storePassword Password to the keystore(s) or {@code null} if not needed
     * @param keyPassword   Password to all entries or {@code null} if not needed
     * @throws GeneralSecurityException When a problem occurs during the processing of the keystore data
     * @throws IOException              If an I/O problem occurs
     */
    public void convert(File inputFile, String inputFormat, File outputFile, String outputFormat, char[] storePassword, char[] keyPassword) throws GeneralSecurityException, IOException {
        final KeyStore inputKeyStore = KeyStore.getInstance(inputFormat);
        try (final FileInputStream inputStream = new FileInputStream(inputFile)) {
            inputKeyStore.load(inputStream, storePassword);
        }

        final KeyStore outputKeyStore = KeyStore.getInstance(outputFormat);
        outputKeyStore.load(null, storePassword);

        final KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(keyPassword);
        for (final String alias : Collections.list(inputKeyStore.aliases())) {
            final KeyStore.ProtectionParameter entryProtection = inputKeyStore.isCertificateEntry(alias) ? null : passwordProtection;
            final KeyStore.Entry entry = inputKeyStore.getEntry(alias, entryProtection);
            outputKeyStore.setEntry(alias, entry, entryProtection);
            // We should copy the creation date here, but there is no public API for all keystores to do that, unfortunately.
        }

        try (final FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputKeyStore.store(outputStream, storePassword);
        }
    }
}
