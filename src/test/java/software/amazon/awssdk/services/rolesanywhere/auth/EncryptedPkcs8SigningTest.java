package software.amazon.awssdk.services.rolesanywhere.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.regions.Region;

/**
 * Proves encrypted PKCS8 keys work end-to-end through CertificateUtils → X509Signer
 * for all encryption schemes supported by the rolesanywhere-credential-helper:
 * 3 ciphers (AES-128/192/256-CBC) × 3 PRFs (HMAC-SHA256/384/512) + scrypt.
 */
class EncryptedPkcs8SigningTest {

    private static final Path CERTS_DIR = Path.of("src/test/resources/certificates");
    private static final char[] PASSWORD = "testpassword".toCharArray();

    /** Combos supported by JDK alone: AES-128/256 × all PRFs. */
    static Stream<Arguments> encryptedKeyFixtures() {
        return Stream.of(
                rsaArgs("RSA aes-128 + SHA256", "encrypted-aes-128-cbc-hmacWithSHA256.pkcs8"),
                rsaArgs("RSA aes-128 + SHA384", "encrypted-aes-128-cbc-hmacWithSHA384.pkcs8"),
                rsaArgs("RSA aes-128 + SHA512", "encrypted-aes-128-cbc-hmacWithSHA512.pkcs8"),
                rsaArgs("RSA aes-256 + SHA256", "encrypted-aes-256-cbc-hmacWithSHA256.pkcs8"),
                rsaArgs("RSA aes-256 + SHA384", "encrypted-aes-256-cbc-hmacWithSHA384.pkcs8"),
                rsaArgs("RSA aes-256 + SHA512", "encrypted-aes-256-cbc-hmacWithSHA512.pkcs8"),
                ecArgs("EC aes-128 + SHA256", "encrypted-ec-aes-128-cbc-hmacWithSHA256.pkcs8"),
                ecArgs("EC aes-128 + SHA384", "encrypted-ec-aes-128-cbc-hmacWithSHA384.pkcs8"),
                ecArgs("EC aes-128 + SHA512", "encrypted-ec-aes-128-cbc-hmacWithSHA512.pkcs8"),
                ecArgs("EC aes-256 + SHA256", "encrypted-ec-aes-256-cbc-hmacWithSHA256.pkcs8"),
                ecArgs("EC aes-256 + SHA384", "encrypted-ec-aes-256-cbc-hmacWithSHA384.pkcs8"),
                ecArgs("EC aes-256 + SHA512", "encrypted-ec-aes-256-cbc-hmacWithSHA512.pkcs8"));
    }

    /** Combos that need a JCE provider (e.g. BouncyCastle): AES-192, scrypt. */
    static Stream<Arguments> unsupportedFixtures() {
        return Stream.of(
                Arguments.of("RSA aes-192 + SHA256", "encrypted-aes-192-cbc-hmacWithSHA256.pkcs8", "RSA"),
                Arguments.of("RSA aes-192 + SHA384", "encrypted-aes-192-cbc-hmacWithSHA384.pkcs8", "RSA"),
                Arguments.of("RSA aes-192 + SHA512", "encrypted-aes-192-cbc-hmacWithSHA512.pkcs8", "RSA"),
                Arguments.of("RSA scrypt", "encrypted-scrypt.pkcs8", "RSA"),
                Arguments.of("EC aes-192 + SHA256", "encrypted-ec-aes-192-cbc-hmacWithSHA256.pkcs8", "EC"),
                Arguments.of("EC aes-192 + SHA384", "encrypted-ec-aes-192-cbc-hmacWithSHA384.pkcs8", "EC"),
                Arguments.of("EC aes-192 + SHA512", "encrypted-ec-aes-192-cbc-hmacWithSHA512.pkcs8", "EC"),
                Arguments.of("EC scrypt", "encrypted-ec-scrypt.pkcs8", "EC"));
    }

    private static Arguments rsaArgs(String name, String file) {
        return Arguments.of(name, file, "RSA", "simple-leaf-key.pem", "simple-leaf.pem", "AWS4-X509-RSA-SHA256");
    }

    private static Arguments ecArgs(String name, String file) {
        return Arguments.of(name, file, "EC", "ec-leaf-key.pem", "ec-leaf.pem", "AWS4-X509-ECDSA-SHA256");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encryptedKeyFixtures")
    void encryptedPkcs8KeyProducesValidSignature(
            String scheme, String filename, String keyType, String refKeyFile, String certFile, String authPrefix)
            throws Exception {
        PrivateKey key = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(filename), keyType, PASSWORD);
        PrivateKey expectedKey = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(refKeyFile), keyType);
        assertArrayEquals(expectedKey.getEncoded(), key.getEncoded(), "Decrypted key must match unencrypted original");

        X509Certificate cert = CertificateUtils.loadCertificate(CERTS_DIR.resolve(certFile));

        X509Signer signer = X509Signer.builder()
                .serviceName("rolesanywhere")
                .region(Region.US_EAST_1)
                .build();

        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .uri(URI.create("https://rolesanywhere.us-east-1.amazonaws.com/sessions"))
                .method(SdkHttpMethod.POST)
                .build();

        SignedRequest signed = signer.sign(request, key, cert);

        assertNotNull(signed);
        String authHeader =
                signed.request().firstMatchingHeader("Authorization").orElse(null);
        assertNotNull(authHeader, "Must have Authorization header");
        assertTrue(authHeader.startsWith(authPrefix), "Expected " + authPrefix + ", got: " + authHeader);

        // Extract Signature= value and verify it's a non-trivial hex string
        // RSA-2048 SHA256 signature = 256 bytes = 512 hex chars
        String signaturePrefix = "Signature=";
        int sigIdx = authHeader.indexOf(signaturePrefix);
        assertTrue(sigIdx > 0, "Authorization must contain Signature=");
        String signature = authHeader.substring(sigIdx + signaturePrefix.length());
        assertFalse(signature.isBlank(), "Signature must not be blank");
        // RSA-2048 = 512 hex; ECDSA P-256 DER = ~130-148 hex
        int minSigLen = 130;
        int maxSigLen = 148;
        if ("RSA".equals(keyType)) {
            minSigLen = 512;
            maxSigLen = 512;
        }
        assertTrue(
                signature.length() >= minSigLen && signature.length() <= maxSigLen,
                "Signature hex length " + signature.length() + " not in [" + minSigLen + "," + maxSigLen + "]");
        assertTrue(signature.matches("[0-9a-f]+"), "Signature must be lowercase hex");
    }

    static Stream<Arguments> allEncryptedFiles() {
        return encryptedKeyFixtures().map(args -> {
            Object[] a = args.get();
            return Arguments.of(a[0], a[1], a[2]);
        });
    }

    @ParameterizedTest(name = "wrong password: {0}")
    @MethodSource("allEncryptedFiles")
    void wrongPasswordThrows(String scheme, String filename, String keyType) {
        assertThrows(
                GeneralSecurityException.class,
                () -> CertificateUtils.loadPrivateKey(
                        CERTS_DIR.resolve(filename), keyType, "wrongpassword".toCharArray()));
    }

    @ParameterizedTest(name = "empty password: {0}")
    @MethodSource("allEncryptedFiles")
    void emptyPasswordThrows(String scheme, String filename, String keyType) {
        assertThrows(
                GeneralSecurityException.class,
                () -> CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(filename), keyType, new char[0]));
    }

    @ParameterizedTest(name = "unsupported without JCE provider: {0}")
    @MethodSource("unsupportedFixtures")
    void unsupportedComboThrowsWithHelpfulMessage(String scheme, String filename, String keyType) {
        GeneralSecurityException ex = assertThrows(
                GeneralSecurityException.class,
                () -> CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(filename), keyType, PASSWORD));
        assertTrue(
                ex.getMessage().contains("provider")
                        || ex.getMessage().contains("scrypt")
                        || ex.getMessage().contains("AES-192"),
                "Should hint at missing provider: " + ex.getMessage());
    }

    static Stream<Arguments> explicitAlgorithmFixtures() {
        return Stream.of(
                Arguments.of(
                        "RSA SHA256+AES128",
                        "encrypted-aes-128-cbc-hmacWithSHA256.pkcs8",
                        "RSA",
                        "simple-leaf-key.pem",
                        "PBEWithHmacSHA256AndAES_128"),
                Arguments.of(
                        "RSA SHA384+AES128",
                        "encrypted-aes-128-cbc-hmacWithSHA384.pkcs8",
                        "RSA",
                        "simple-leaf-key.pem",
                        "PBEWithHmacSHA384AndAES_128"),
                Arguments.of(
                        "RSA SHA512+AES128",
                        "encrypted-aes-128-cbc-hmacWithSHA512.pkcs8",
                        "RSA",
                        "simple-leaf-key.pem",
                        "PBEWithHmacSHA512AndAES_128"),
                Arguments.of(
                        "RSA SHA256+AES256",
                        "encrypted-aes-256-cbc-hmacWithSHA256.pkcs8",
                        "RSA",
                        "simple-leaf-key.pem",
                        "PBEWithHmacSHA256AndAES_256"),
                Arguments.of(
                        "RSA SHA384+AES256",
                        "encrypted-aes-256-cbc-hmacWithSHA384.pkcs8",
                        "RSA",
                        "simple-leaf-key.pem",
                        "PBEWithHmacSHA384AndAES_256"),
                Arguments.of(
                        "RSA SHA512+AES256",
                        "encrypted-aes-256-cbc-hmacWithSHA512.pkcs8",
                        "RSA",
                        "simple-leaf-key.pem",
                        "PBEWithHmacSHA512AndAES_256"),
                Arguments.of(
                        "EC SHA256+AES256",
                        "encrypted-ec-aes-256-cbc-hmacWithSHA256.pkcs8",
                        "EC",
                        "ec-leaf-key.pem",
                        "PBEWithHmacSHA256AndAES_256"));
    }

    @ParameterizedTest(name = "explicit algorithm: {0}")
    @MethodSource("explicitAlgorithmFixtures")
    void explicitAlgorithmWorks(String scheme, String filename, String keyType, String refKey, String algorithm)
            throws Exception {
        PrivateKey key = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(filename), keyType, PASSWORD, algorithm);
        PrivateKey expected = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(refKey), keyType);
        assertArrayEquals(expected.getEncoded(), key.getEncoded());
    }

    static Stream<Arguments> invalidAlgorithms() {
        return Stream.of(
                Arguments.of("nonsense", "NotARealAlgorithm"),
                Arguments.of("empty", ""),
                Arguments.of("close but wrong", "PBEWithHmacSHA256AndAES_192"));
    }

    @ParameterizedTest(name = "invalid algorithm: {0}")
    @MethodSource("invalidAlgorithms")
    void invalidAlgorithmThrows(String label, String algorithm) {
        assertThrows(
                GeneralSecurityException.class,
                () -> CertificateUtils.loadPrivateKey(
                        CERTS_DIR.resolve("encrypted-aes-256-cbc-hmacWithSHA256.pkcs8"), "RSA", PASSWORD, algorithm));
    }

    static Stream<Arguments> unencryptedKeys() {
        return Stream.of(Arguments.of("RSA", "simple-leaf-key.pem"), Arguments.of("EC", "ec-leaf-key.pem"));
    }

    @ParameterizedTest(name = "unencrypted {0} with password throws")
    @MethodSource("unencryptedKeys")
    void unencryptedKeyWithPasswordThrows(String keyType, String file) {
        GeneralSecurityException ex = assertThrows(
                GeneralSecurityException.class,
                () -> CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(file), keyType, PASSWORD));
        assertTrue(
                ex.getMessage().contains("not encrypted"), "Should hint that key is not encrypted: " + ex.getMessage());
    }

    @Test
    void encryptedDerKeyDecryptsCorrectly() throws Exception {
        PrivateKey key = CertificateUtils.loadEncryptedDerPrivateKey(
                CERTS_DIR.resolve("encrypted-aes-256-cbc.der"), "RSA", PASSWORD);
        PrivateKey expectedKey = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve("simple-leaf-key.pem"), "RSA");
        assertArrayEquals(
                expectedKey.getEncoded(), key.getEncoded(), "DER-decrypted key must match unencrypted original");
    }

    @Test
    void encryptedEcDerKeyDecryptsCorrectly() throws Exception {
        PrivateKey key = CertificateUtils.loadEncryptedDerPrivateKey(
                CERTS_DIR.resolve("encrypted-ec-aes-256-cbc.der"), "EC", PASSWORD);
        PrivateKey expectedKey = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve("ec-leaf-key.pem"), "EC");
        assertArrayEquals(
                expectedKey.getEncoded(), key.getEncoded(), "DER-decrypted EC key must match unencrypted original");
    }

    @Test
    void corruptedFileThrows() throws IOException {
        Path corrupted = Files.createTempFile("corrupted", ".pkcs8");
        Files.writeString(
                corrupted,
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                        + "dGhpcyBpcyBub3QgYSByZWFsIGtleQ==\n"
                        + "-----END ENCRYPTED PRIVATE KEY-----\n");
        try {
            GeneralSecurityException ex = assertThrows(
                    GeneralSecurityException.class, () -> CertificateUtils.loadPrivateKey(corrupted, "RSA", PASSWORD));
            assertTrue(
                    ex.getMessage().contains("parse") || ex.getMessage().contains("PBES2"),
                    "Should hint at parse failure: " + ex.getMessage());
        } finally {
            Files.deleteIfExists(corrupted);
        }
    }
}
