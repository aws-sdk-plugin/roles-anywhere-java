package software.amazon.rolesanywhere.plugin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Pattern;
import software.amazon.awssdk.annotations.SdkInternalApi;
import software.amazon.awssdk.utils.Logger;

/**
 * Utility class for working with X.509 certificates and private keys.
 * Provides methods for loading, parsing, and converting certificates and keys
 * between different formats (PEM, DER, Base64).
 */
@SdkInternalApi
final class CertificateUtils {

    private static final Pattern PEM_PATTERN = Pattern.compile("-----(BEGIN|END)[A-Z0-9 ]+-----");
    private static final Logger LOG = Logger.loggerFor(CertificateUtils.class);

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CertificateUtils() {
        // Utility class
    }

    /**
     * Encode certificate as base64-encoded DER. This is NOT a PEM encoding (no
     * prologue or epilogue lines)
     *
     * @param certificate the X.509 certificate to encode
     * @return Base64 string representation of the certificate
     * @throws CertificateEncodingException if the certificate cannot be encoded
     */
    public static String certificateToString(X509Certificate certificate) throws CertificateEncodingException {
        ValidationUtils.validateCertificate(certificate);
        return Base64.getEncoder().encodeToString(certificate.getEncoded()).trim();
    }

    /**
     * Load an X509Certificate from a filepath.
     *
     * @param path Path to the certificate file
     * @return X509Certificate
     * @throws CertificateException if the certificate cannot be loaded
     * @throws IOException          if the file cannot be read
     */
    public static X509Certificate loadCertificate(Path path) throws CertificateException, IOException {
        byte[] certData = Files.readAllBytes(path);
        String certString = new String(certData, StandardCharsets.UTF_8);
        return readCertificateData(certString);
    }

    /**
     * Load a PrivateKey from a filepath.
     *
     * @param path    Path to the private key file
     * @param keyType Encryption Algorithm e.g. RSA
     * @return PrivateKey
     * @throws GeneralSecurityException if the key cannot be loaded
     * @throws IOException              if the file cannot be read
     */
    public static PrivateKey loadPrivateKey(Path path, String keyType) throws GeneralSecurityException, IOException {
        warnIfInsecurePermissions(path);
        byte[] keyData = Files.readAllBytes(path);
        try {
            String keyString = new String(keyData, StandardCharsets.UTF_8);
            return readPrivateKeyFromString(keyString, keyType);
        } finally {
            SecurityUtils.clear(keyData);
        }
    }

    /**
     * Load a password protected PrivateKey from a filepath.
     *
     * @param path    Path to the private key file
     * @param keyType Encryption Algorithm e.g. RSA
     * @param password Decrypts the key using this password (caller should zero after use)
     * @return PrivateKey
     * @throws GeneralSecurityException if the key cannot be loaded
     * @throws IOException              if the file cannot be read
     */
    public static PrivateKey loadPrivateKey(Path path, String keyType, char[] password)
            throws GeneralSecurityException, IOException {
        warnIfInsecurePermissions(path);
        byte[] derBytes = readEncryptedPem(path);
        try {
            return Pbes2Decoder.decrypt(derBytes, password, keyType);
        } finally {
            SecurityUtils.clear(derBytes);
        }
    }

    /**
     * Load a password-protected PrivateKey with an explicit JCE algorithm.
     * Bypasses ASN.1 auto-detection. Works with any registered JCE provider
     * including BouncyCastle for scrypt.
     *
     * @param path      Path to the PEM-encoded encrypted PKCS#8 key file
     * @param keyType   Key algorithm e.g. RSA, EC
     * @param password  Decrypts the key using this password (caller should zero after use)
     * @param algorithm JCE algorithm name e.g. "PBEWithHmacSHA256AndAES_256"
     * @return PrivateKey
     * @throws GeneralSecurityException if the key cannot be loaded
     * @throws IOException              if the file cannot be read
     */
    public static PrivateKey loadPrivateKey(Path path, String keyType, char[] password, String algorithm)
            throws GeneralSecurityException, IOException {
        warnIfInsecurePermissions(path);
        byte[] derBytes = readEncryptedPem(path);
        try {
            return Pbes2Decoder.decrypt(derBytes, password, keyType, algorithm);
        } finally {
            SecurityUtils.clear(derBytes);
        }
    }

    /**
     * Load a password-protected PrivateKey from a DER-encoded file.
     * Auto-detects the encryption algorithm.
     *
     * @param path     Path to the DER-encoded encrypted PKCS#8 key file
     * @param keyType  Encryption Algorithm e.g. RSA
     * @param password Decrypts the key using this password (caller should zero after use)
     * @return PrivateKey
     * @throws GeneralSecurityException if the key cannot be loaded
     * @throws IOException              if the file cannot be read
     */
    public static PrivateKey loadEncryptedDerPrivateKey(Path path, String keyType, char[] password)
            throws GeneralSecurityException, IOException {
        warnIfInsecurePermissions(path);
        byte[] derBytes = readEncryptedDer(path);
        try {
            return Pbes2Decoder.decrypt(derBytes, password, keyType);
        } finally {
            SecurityUtils.clear(derBytes);
        }
    }

    /**
     * Load a password-protected PrivateKey from a DER-encoded file
     * with an explicit JCE algorithm.
     *
     * @param path      Path to the DER-encoded encrypted PKCS#8 key file
     * @param keyType   Key algorithm e.g. RSA, EC
     * @param password  Decrypts the key using this password (caller should zero after use)
     * @param algorithm JCE algorithm name
     * @return PrivateKey
     * @throws GeneralSecurityException if the key cannot be loaded
     * @throws IOException              if the file cannot be read
     */
    public static PrivateKey loadEncryptedDerPrivateKey(Path path, String keyType, char[] password, String algorithm)
            throws GeneralSecurityException, IOException {
        warnIfInsecurePermissions(path);
        byte[] derBytes = readEncryptedDer(path);
        try {
            return Pbes2Decoder.decrypt(derBytes, password, keyType, algorithm);
        } finally {
            SecurityUtils.clear(derBytes);
        }
    }

    private static void warnIfInsecurePermissions(Path path) {
        try {
            if (!path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                return;
            }
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            if (perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.OTHERS_READ)) {
                LOG.warn(() -> "Private key file " + path
                        + " has permissions " + PosixFilePermissions.toString(perms)
                        + " — it is readable by group or others. "
                        + "Recommended: chmod 600 " + path);
            }
        } catch (Exception e) {
            // Best-effort — don't fail key loading because of a permission check error
            LOG.debug(() -> "Could not check permissions on " + path + ": " + e.getMessage());
        }
    }

    private static byte[] readEncryptedPem(Path path) throws GeneralSecurityException, IOException {
        byte[] keyData = Files.readAllBytes(path);
        try {
            String keyString = new String(keyData, StandardCharsets.UTF_8);
            if (keyString.contains("BEGIN RSA PRIVATE KEY")
                    || keyString.contains("BEGIN EC PRIVATE KEY")
                    || (keyString.contains("BEGIN PRIVATE KEY")
                            && !keyString.contains("BEGIN ENCRYPTED PRIVATE KEY"))) {
                throw new GeneralSecurityException("Key file is not encrypted. "
                        + "Use loadPrivateKey(path, keyType) instead, "
                        + "or encrypt with: openssl pkcs8 -topk8 -v2 aes-256-cbc");
            }
            if (!keyString.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
                throw new GeneralSecurityException("File does not appear to be a PEM-encoded encrypted "
                        + "PKCS#8 key. For DER-encoded files use "
                        + "loadEncryptedDerPrivateKey().");
            }
            try {
                return Base64.getDecoder().decode(trimPemData(keyString));
            } catch (IllegalArgumentException e) {
                throw new GeneralSecurityException("Failed to Base64-decode PEM content", e);
            }
        } finally {
            SecurityUtils.clear(keyData);
        }
    }

    private static byte[] readEncryptedDer(Path path) throws GeneralSecurityException, IOException {
        byte[] derBytes = Files.readAllBytes(path);
        if (derBytes.length > 10 && new String(derBytes, 0, 10, StandardCharsets.US_ASCII).startsWith("-----BEGIN")) {
            SecurityUtils.clear(derBytes);
            throw new GeneralSecurityException("File appears to be PEM-encoded, not DER. "
                    + "Use loadPrivateKey(path, keyType, password) instead.");
        }
        return derBytes;
    }

    /**
     * Parse a string into an X509Certificate. The string MUST be either -
     * <p>
     * Base64-encoded DER data. The data is trimmed, decoded, and passed as a byte
     * array to the certificate parser
     * * PEM-encoded data (which is Base64-encoded DER data with a header, footer,
     * and whitespace). The PEM
     * string is converted directly to a byte array and passed to the certificate
     * parser.
     * </p>
     *
     * @param pemData String to parse; must be one of the formats described above
     * @return Valid X509Certificate
     * @throws CertificateException If pemData cannot be parsed
     */
    public static X509Certificate readCertificateData(String pemData) throws CertificateException {
        ValidationUtils.requireNonNullAndNonEmpty(pemData, "pemData");
        byte[] decoded;
        if (isPemData(pemData)) {
            decoded = pemData.getBytes(StandardCharsets.UTF_8);
        } else {
            decoded = Base64.getMimeDecoder().decode(pemData.trim());
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(decoded);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    /**
     * Read a private key from the PEM input string, of the specified key type.
     *
     * @param pemData The pemData to parse into a PrivateKey object.
     * @param keyType RSA or EC - the value from the corresponding certificate's
     *                public key may be used, for example
     * @return Decoded key
     * @throws GeneralSecurityException if the key cannot be read or parsed
     */
    public static PrivateKey readPrivateKeyFromString(String pemData, String keyType) throws GeneralSecurityException {
        byte[] privateKeyData = null;
        try {
            String keyString = trimPemData(pemData);
            privateKeyData = Base64.getDecoder().decode(keyString);
            KeyFactory keyFactory = KeyFactory.getInstance(keyType);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyData);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new GeneralSecurityException("Could not read private key", e);
        } finally {
            SecurityUtils.clear(privateKeyData);
        }
    }

    /**
     * Checks whether the string contains data in the PEM format.
     *
     * @param certData a string holding the certificate data to be checked
     * @return true if the certificate data is PEM formatted
     */
    public static boolean isPemData(String certData) {
        return PEM_PATTERN.matcher(certData).find();
    }

    /**
     * Trims the PEM header and footer, and removes newlines from the data.
     *
     * @param pemData Data to clean
     * @return Single line Base-64 string, suitable for parsing.
     */
    public static String trimPemData(String pemData) {
        return PEM_PATTERN
                .matcher(pemData)
                .replaceAll("")
                .replace("\n", "") // remove newline in combination with below also removes \r\n
                .replace("\r", ""); // remove other kinds of newline
    }
}
