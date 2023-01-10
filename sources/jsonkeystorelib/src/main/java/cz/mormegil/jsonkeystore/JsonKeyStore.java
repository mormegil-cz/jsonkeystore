package cz.mormegil.jsonkeystore;

import net.iharder.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * KeyStore SPI providing a new simple portable format for keystores using a simple readable JSON.
 */
public class JsonKeyStore extends KeyStoreSpi {
    private static final String ATTR_ENTRIES = "entries";
    private static final String ATTR_TYPE = "type";
    private static final String ATTR_ATTRIBUTES = "attributes";
    private static final String ATTR_DATE = "date";
    private static final String ENTRY_TYPE_PRIVATE_KEY = "PrivateKey";
    private static final String ENTRY_TYPE_SECRET_KEY = "SecretKey";
    private static final String ENTRY_TYPE_TRUSTED_CERTIFICATE = "TrustedCertificate";

    private final Map<String, KeyStore.Entry> entries = new HashMap<>();
    private final Map<String, Date> entryDates = new HashMap<>();

    private <T> Optional<T> getEntry(String alias, Class<? extends T> clazz) {
        final KeyStore.Entry entry = entries.get(alias);
        if (entry == null || !clazz.isAssignableFrom(entry.getClass())) {
            return Optional.empty();
        }

        @SuppressWarnings("unchecked")
        final T castedEntry = (T) entry;

        return Optional.of(castedEntry);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Key engineGetKey(String alias, char[] password) {
        if (!entries.containsKey(alias)) {
            return null;
        }

        final Optional<KeyStore.PrivateKeyEntry> privateKeyEntry = getEntry(alias, KeyStore.PrivateKeyEntry.class);
        if (privateKeyEntry.isPresent()) {
            return privateKeyEntry.get().getPrivateKey();
        }

        final Optional<KeyStore.SecretKeyEntry> secretKeyEntry = getEntry(alias, KeyStore.SecretKeyEntry.class);
        //noinspection OptionalIsPresent
        if (secretKeyEntry.isPresent()) {
            return secretKeyEntry.get().getSecretKey();
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return getEntry(alias, KeyStore.PrivateKeyEntry.class)
                .map(KeyStore.PrivateKeyEntry::getCertificateChain)
                .map(Certificate[]::clone)
                .orElse(null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Certificate engineGetCertificate(String alias) {
        if (!entries.containsKey(alias)) {
            return null;
        }

        final Optional<KeyStore.TrustedCertificateEntry> trustedCertificateEntry = getEntry(alias, KeyStore.TrustedCertificateEntry.class);
        if (trustedCertificateEntry.isPresent()) {
            return trustedCertificateEntry.get().getTrustedCertificate();
        }

        final Optional<KeyStore.PrivateKeyEntry> privateKeyEntry = getEntry(alias, KeyStore.PrivateKeyEntry.class);
        if (privateKeyEntry.isPresent()) {
            final Certificate[] certificateChain = privateKeyEntry.get().getCertificateChain();
            return certificateChain.length > 0 ? certificateChain[0] : null;
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date engineGetCreationDate(String alias) {
        return entryDates.get(alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        final KeyStore.Entry existingEntry = entries.get(alias);

        final KeyStore.Entry newEntry;
        final Set<KeyStore.Entry.Attribute> attributes = existingEntry == null ? Collections.emptySet() : existingEntry.getAttributes();
        if (key instanceof PrivateKey) {
            if (existingEntry != null && !(existingEntry instanceof KeyStore.PrivateKeyEntry)) {
                throw new KeyStoreException("The alias already exists and is not a private key entry");
            }
            newEntry = new KeyStore.PrivateKeyEntry((PrivateKey) key, chain.clone(), attributes);
        } else if (key instanceof SecretKey) {
            if (existingEntry != null && !(existingEntry instanceof KeyStore.SecretKeyEntry)) {
                throw new KeyStoreException("The alias already exists and is not a private key entry");
            }
            newEntry = new KeyStore.SecretKeyEntry((SecretKey) key, attributes);
        } else {
            throw new IllegalArgumentException("Unsupported key type to store");
        }

        entries.put(alias, newEntry);
        if (existingEntry == null) {
            entryDates.put(alias, new Date());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        // TODO: This is a very strange method: a byte array without any accompanying specification;
        // If the entry already exists, we might use it and parse the key, nothing complicated there.
        // But if the entry does not exist, what parameters should we use?
        throw new KeyStoreException("Unsupported operation");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        final KeyStore.Entry existingEntry = entries.get(alias);
        if (existingEntry != null && !(existingEntry instanceof KeyStore.TrustedCertificateEntry)) {
            throw new KeyStoreException("The alias already exists and is not a trusted certificate entry");
        }

        final Set<KeyStore.Entry.Attribute> attributes = existingEntry == null ? Collections.emptySet() : existingEntry.getAttributes();
        final KeyStore.Entry newEntry = new KeyStore.TrustedCertificateEntry(cert, attributes);

        entries.put(alias, newEntry);
        if (existingEntry == null) {
            entryDates.put(alias, new Date());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void engineDeleteEntry(String alias) {
        entries.remove(alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(entries.keySet());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean engineContainsAlias(String alias) {
        return entries.containsKey(alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int engineSize() {
        return entries.size();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean engineIsKeyEntry(String alias) {
        final KeyStore.Entry entry = entries.get(alias);
        return entry instanceof KeyStore.PrivateKeyEntry
                || entry instanceof KeyStore.SecretKeyEntry;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return entries.get(alias) instanceof KeyStore.TrustedCertificateEntry;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        Objects.requireNonNull(cert);

        for (final String alias : entries.keySet()) {
            final Certificate certificate = engineGetCertificate(alias);
            if (cert.equals(certificate)) {
                return alias;
            }
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, CertificateException {
        final JSONObject json = new JSONObject();
        final JSONObject entriesJson = new JSONObject();
        json.put(ATTR_ENTRIES, entriesJson);

        for (final Map.Entry<String, KeyStore.Entry> keyStoreEntry : entries.entrySet()) {
            final String alias = keyStoreEntry.getKey();
            final KeyStore.Entry entry = keyStoreEntry.getValue();

            final JSONObject itemJson = new JSONObject();
            entriesJson.put(alias, itemJson);

            if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) entry;
                itemJson.put(ATTR_TYPE, ENTRY_TYPE_PRIVATE_KEY);
                itemJson.put("key", convertKeyToJson(keyEntry.getPrivateKey()));
                itemJson.put("certificateChain", convertCertificateChainToJson(keyEntry.getCertificateChain()));
            } else if (entry instanceof KeyStore.SecretKeyEntry) {
                final KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) entry;
                itemJson.put(ATTR_TYPE, ENTRY_TYPE_SECRET_KEY);
                itemJson.put("key", convertKeyToJson(keyEntry.getSecretKey()));
            } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                final KeyStore.TrustedCertificateEntry certificateEntry = (KeyStore.TrustedCertificateEntry) entry;
                itemJson.put(ATTR_TYPE, ENTRY_TYPE_TRUSTED_CERTIFICATE);
                itemJson.put("certificate", convertCertificateToJson(certificateEntry.getTrustedCertificate()));
            } else {
                throw new UnsupportedOperationException("Unsupported entry type");
            }
            final Set<KeyStore.Entry.Attribute> entryAttributes = entry.getAttributes();
            if (!entryAttributes.isEmpty()) {
                final JSONObject attributesJson = new JSONObject();
                for (final KeyStore.Entry.Attribute attribute : entryAttributes) {
                    attributesJson.put(attribute.getName(), attribute.getValue());
                }
                itemJson.put(ATTR_ATTRIBUTES, attributesJson);
            }
            itemJson.put(ATTR_DATE, dateToJson(entryDates.get(alias)));
        }

        try (final Writer writer = new BufferedWriter(new OutputStreamWriter(stream, StandardCharsets.UTF_8))) {
            writer.write(json.toString(4));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream == null) {
            // strange but supported: no-op
            return;
        }

        try {
            final JSONObject json = new JSONObject(new JSONTokener(stream));
            final JSONObject entriesJson = json.getJSONObject(ATTR_ENTRIES);

            for (final String alias : entriesJson.keySet()) {
                final JSONObject entry = entriesJson.getJSONObject(alias);

                final Set<KeyStore.Entry.Attribute> attributes = parseAttributesFromJson(entry);
                final String type = entry.getString(ATTR_TYPE);
                switch (type) {
                    case ENTRY_TYPE_PRIVATE_KEY:
                        final PrivateKey privateKey = parsePrivateKeyFromJson(entry.getJSONObject("key"));
                        final Certificate[] chain = parseCertificateChainFromJson(entry.getJSONArray("certificateChain"));
                        entries.put(alias, new KeyStore.PrivateKeyEntry(privateKey, chain, attributes));
                        break;

                    case ENTRY_TYPE_SECRET_KEY:
                        final SecretKey secretKey = parseSecretKeyFromJson(entry.getJSONObject("key"));
                        entries.put(alias, new KeyStore.SecretKeyEntry(secretKey, attributes));
                        break;

                    case ENTRY_TYPE_TRUSTED_CERTIFICATE:
                        final Certificate trustedCert = parseCertificateFromJson(entry.getJSONObject("certificate"));
                        entries.put(alias, new KeyStore.TrustedCertificateEntry(trustedCert, attributes));
                        break;

                    default:
                        throw new IOException("Unknown entry type in JSON KeyStore: " + type);
                }

                entryDates.put(alias, jsonToDate(entry.getString(ATTR_DATE)));
            }
        } catch (JSONException e) {
            throw new IOException("Not a valid JSON keystore", e);
        }
    }

    private static JSONObject convertCertificateToJson(Certificate certificate) throws CertificateEncodingException {
        final JSONObject result = new JSONObject();
        result.put(ATTR_TYPE, certificate.getClass().getName());
        result.put("certificateType", certificate.getType());
        result.put("encoded", Base64.encodeBytes(certificate.getEncoded()));
        return result;
    }

    private static Certificate parseCertificateFromJson(JSONObject certJson) throws CertificateException, IOException {
        final String type = certJson.getString("certificateType");
        final byte[] encoded = Base64.decode(certJson.getString("encoded"));

        final CertificateFactory certificateFactory = CertificateFactory.getInstance(type);
        try (final ByteArrayInputStream memoryStream = new ByteArrayInputStream(encoded)) {
            return certificateFactory.generateCertificate(memoryStream);
        }
    }

    private static JSONArray convertCertificateChainToJson(Certificate[] certificates) throws CertificateEncodingException {
        final JSONArray result = new JSONArray();
        for (final Certificate certificate : certificates) {
            result.put(convertCertificateToJson(certificate));
        }
        return result;
    }

    private static Certificate[] parseCertificateChainFromJson(JSONArray certificateChain) throws CertificateException, IOException {
        final int count = certificateChain.length();
        final Certificate[] result = new Certificate[count];
        for (int i = 0; i < count; ++i) {
            result[i] = parseCertificateFromJson(certificateChain.getJSONObject(i));
        }
        return result;
    }

    private static JSONObject convertKeyToJson(Key key) {
        final JSONObject result = new JSONObject();
        result.put(ATTR_TYPE, key.getClass().getName());
        result.put("algorithm", key.getAlgorithm());
        result.put("format", key.getFormat());
        result.put("encoded", Base64.encodeBytes(key.getEncoded()));
        return result;
    }

    private PrivateKey parsePrivateKeyFromJson(JSONObject keyJson) throws IOException, NoSuchAlgorithmException {
        final String algorithm = keyJson.getString("algorithm");
        final String format = keyJson.getString("format");
        final byte[] encoded = Base64.decode(keyJson.getString("encoded"));

        final Key translatedKey;
        final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        try {
            translatedKey = keyFactory.translateKey(new PrivateKeyBlueprint(algorithm, format, encoded));
        } catch (InvalidKeyException e) {
            throw new NoSuchAlgorithmException("Unable to process key", e);
        }
        if (!(translatedKey instanceof PrivateKey)) {
            throw new NoSuchAlgorithmException("Unexpected type of key");
        }
        return (PrivateKey) translatedKey;
    }

    private SecretKey parseSecretKeyFromJson(JSONObject keyJson) throws IOException, NoSuchAlgorithmException {
        final String algorithm = keyJson.getString("algorithm");
        final String format = keyJson.getString("format");
        final byte[] encoded = Base64.decode(keyJson.getString("encoded"));

        if ("RAW".equals(algorithm) && "RAW".equals(format)) {
            return new SecretKeySpec(encoded, algorithm);
        }

        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        try {
            return secretKeyFactory.translateKey(new SecretKeyBlueprint(algorithm, format, encoded));
        } catch (InvalidKeyException e) {
            throw new NoSuchAlgorithmException("Unable to process key", e);
        }
    }

    private static Set<KeyStore.Entry.Attribute> parseAttributesFromJson(JSONObject entryJson) {
        if (entryJson.isNull(ATTR_ATTRIBUTES)) {
            return Collections.emptySet();
        }
        final JSONObject attributesJson = entryJson.getJSONObject(ATTR_ATTRIBUTES);

        final Set<KeyStore.Entry.Attribute> result = new HashSet<>(entryJson.length());
        for (final String key : attributesJson.keySet()) {
            result.add(new SimpleAttribute(key, attributesJson.getString(key)));
        }
        return result;
    }

    private static String dateToJson(Date date) {
        return date.toInstant().toString();
    }

    private static Date jsonToDate(String isoStr) {
        try {
            return Date.from(Instant.parse(isoStr));
        } catch (DateTimeParseException | IllegalArgumentException e) {
            throw new JSONException("Invalid date/time format", e);
        }
    }

    private static class SimpleAttribute implements KeyStore.Entry.Attribute {
        private final String name;
        private final String value;

        public SimpleAttribute(String name, String value) {
            this.name = name;
            this.value = value;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getValue() {
            return value;
        }
    }

    private static abstract class KeyBlueprint implements Key {
        private final String algorithm;
        private final String format;
        private final byte[] encoded;

        protected KeyBlueprint(String algorithm, String format, byte[] encoded) {
            this.algorithm = algorithm;
            this.format = format;
            this.encoded = encoded;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return format;
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }
    }

    private static class SecretKeyBlueprint extends KeyBlueprint implements SecretKey {
        public SecretKeyBlueprint(String algorithm, String format, byte[] encoded) {
            super(algorithm, format, encoded);
        }
    }

    private static class PrivateKeyBlueprint extends KeyBlueprint implements PrivateKey {
        public PrivateKeyBlueprint(String algorithm, String format, byte[] encoded) {
            super(algorithm, format, encoded);
        }
    }
}
