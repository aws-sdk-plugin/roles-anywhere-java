package software.amazon.rolesanywhere.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for {@link CertificateUtils#readPrivateKeyFromString} and
 * {@link CertificateUtils#loadPrivateKey(Path, String)}, verifying
 * functional correctness after adding zeroization of intermediate
 * byte arrays and insecure-permission warnings.
 */
class CertificateUtilsTest {

    private static final Path CERTS_DIR = Path.of("src/test/resources/certificates");

    static Stream<Arguments> keyFixtures() {
        return Stream.of(Arguments.of("RSA", "simple-leaf-key.pem"), Arguments.of("EC", "ec-leaf-key.pem"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyFixtures")
    void readPrivateKeyFromStringReturnsValidKey(String keyType, String fileName) throws Exception {
        String pemData = Files.readString(CERTS_DIR.resolve(fileName), StandardCharsets.UTF_8);

        PrivateKey key = CertificateUtils.readPrivateKeyFromString(pemData, keyType);

        assertNotNull(key);
        assertEquals(keyType, key.getAlgorithm());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyFixtures")
    void loadPrivateKeyReturnsValidKey(String keyType, String fileName) throws Exception {
        PrivateKey key = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve(fileName), keyType);

        assertNotNull(key);
        assertEquals(keyType, key.getAlgorithm());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyFixtures")
    void readPrivateKeyFromStringAndLoadPrivateKeyProduceSameKey(String keyType, String fileName) throws Exception {
        Path keyPath = CERTS_DIR.resolve(fileName);
        String pemData = Files.readString(keyPath, StandardCharsets.UTF_8);

        PrivateKey fromString = CertificateUtils.readPrivateKeyFromString(pemData, keyType);
        PrivateKey fromFile = CertificateUtils.loadPrivateKey(keyPath, keyType);

        assertEquals(fromString, fromFile);
    }

    @Test
    void readPrivateKeyFromStringInvalidBase64Throws() {
        assertThrows(
                GeneralSecurityException.class,
                () -> CertificateUtils.readPrivateKeyFromString("not-valid-pem!!!", "RSA"));
    }

    @Test
    void readPrivateKeyFromStringWrongKeyTypeThrows() throws Exception {
        String rsaPem = Files.readString(CERTS_DIR.resolve("simple-leaf-key.pem"), StandardCharsets.UTF_8);

        assertThrows(GeneralSecurityException.class, () -> CertificateUtils.readPrivateKeyFromString(rsaPem, "EC"));
    }

    @Test
    void loadPrivateKeyNonexistentFileThrows() {
        assertThrows(Exception.class, () -> CertificateUtils.loadPrivateKey(Path.of("nonexistent-key.pem"), "RSA"));
    }

    /**
     * Verifies that loading a key file with insecure (world-readable) permissions
     * still succeeds — the warning is best-effort and must not break key loading.
     */
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void loadPrivateKeyWithInsecurePermissionsStillSucceeds(@TempDir Path tempDir) throws Exception {
        Path source = CERTS_DIR.resolve("simple-leaf-key.pem");
        Path insecureKey = tempDir.resolve("insecure-key.pem");
        Files.copy(source, insecureKey);
        Files.setPosixFilePermissions(insecureKey, PosixFilePermissions.fromString("rw-r--r--"));

        PrivateKey key = CertificateUtils.loadPrivateKey(insecureKey, "RSA");

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
    }

    /**
     * Verifies that loading a key file with secure (owner-only) permissions succeeds.
     */
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void loadPrivateKeyWithSecurePermissionsSucceeds(@TempDir Path tempDir) throws Exception {
        Path source = CERTS_DIR.resolve("simple-leaf-key.pem");
        Path secureKey = tempDir.resolve("secure-key.pem");
        Files.copy(source, secureKey);
        Files.setPosixFilePermissions(secureKey, PosixFilePermissions.fromString("rw-------"));

        PrivateKey key = CertificateUtils.loadPrivateKey(secureKey, "RSA");

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    void toStringRedactsSerialAndOmitsSubject() throws Exception {
        X509Certificate cert = CertificateUtils.loadCertificate(CERTS_DIR.resolve("simple-leaf.pem"));
        PrivateKey key = CertificateUtils.loadPrivateKey(CERTS_DIR.resolve("simple-leaf-key.pem"), "RSA");
        X509Identity identity = new X509Identity(cert, key);

        String result = identity.toString();

        assertTrue(result.startsWith("X509Credentials{serialNumber=***"));
        assertTrue(result.contains("chainSize="));
        assertFalse(result.contains("subject"), "subject DN must not appear in toString");
        // Full serial must not appear
        String fullSerial = cert.getSerialNumber().toString();
        assertFalse(result.contains(fullSerial), "full serial must not appear in toString");
        // Last 4 digits should appear
        String lastFour = fullSerial.substring(Math.max(0, fullSerial.length() - 4));
        assertTrue(result.contains("***" + lastFour));
    }
}
