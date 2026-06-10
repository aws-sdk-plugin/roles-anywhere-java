package software.amazon.awssdk.services.rolesanywhere.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ValidationUtilsTest {

    @ParameterizedTest
    @MethodSource("requireNonNullAndNonEmptyProvider")
    void testRequireNonNullAndNonEmpty(String value, boolean shouldThrow, String expectedMessage) {
        if (shouldThrow) {
            IllegalArgumentException ex = assertThrows(
                    IllegalArgumentException.class,
                    () -> ValidationUtils.requireNonNullAndNonEmpty(value, "testParam"));
            assertTrue(ex.getMessage().contains(expectedMessage));
        } else {
            assertDoesNotThrow(() -> ValidationUtils.requireNonNullAndNonEmpty(value, "testParam"));
        }
    }

    static Stream<Arguments> requireNonNullAndNonEmptyProvider() {
        return Stream.of(
                Arguments.of(null, true, "is required, but was null"),
                Arguments.of("", true, "cannot be empty or whitespace-only"),
                Arguments.of("   ", true, "cannot be empty or whitespace-only"),
                Arguments.of("valid", false, null));
    }

    @ParameterizedTest
    @MethodSource("requireParameterProvider")
    void testRequireParameter(Object value, boolean shouldThrow) {
        if (shouldThrow) {
            IllegalArgumentException ex = assertThrows(
                    IllegalArgumentException.class, () -> ValidationUtils.requireParameter(value, "testParam"));
            assertTrue(ex.getMessage().contains("is required, but was null"));
        } else {
            assertDoesNotThrow(() -> ValidationUtils.requireParameter(value, "testParam"));
        }
    }

    static Stream<Arguments> requireParameterProvider() {
        return Stream.of(Arguments.of(null, true), Arguments.of("value", false), Arguments.of(123, false));
    }

    @ParameterizedTest
    @MethodSource("nullOrEmptyStringProvider")
    void testNullOrEmptyString(String value, boolean expected) {
        assertEquals(expected, ValidationUtils.nullOrEmpty(value));
    }

    static Stream<Arguments> nullOrEmptyStringProvider() {
        return Stream.of(
                Arguments.of(null, true),
                Arguments.of("", true),
                Arguments.of("   ", true),
                Arguments.of("value", false));
    }

    @ParameterizedTest
    @MethodSource("nullOrEmptyByteArrayProvider")
    void testNullOrEmptyByteArray(byte[] value, boolean expected) {
        assertEquals(expected, ValidationUtils.nullOrEmpty(value));
    }

    static Stream<Arguments> nullOrEmptyByteArrayProvider() {
        return Stream.of(
                Arguments.of(null, true), Arguments.of(new byte[0], true), Arguments.of(new byte[] {1, 2, 3}, false));
    }

    @ParameterizedTest
    @MethodSource("validateCertificateProvider")
    void testValidateCertificate(X509Certificate cert, boolean shouldThrow) {
        if (shouldThrow) {
            assertThrows(IllegalArgumentException.class, () -> ValidationUtils.validateCertificate(cert));
        } else {
            assertDoesNotThrow(() -> ValidationUtils.validateCertificate(cert));
        }
    }

    static Stream<Arguments> validateCertificateProvider() throws CertificateEncodingException {
        X509Certificate validCert = mock(X509Certificate.class);
        when(validCert.getEncoded()).thenReturn(new byte[] {1, 2, 3});

        X509Certificate emptyCert = mock(X509Certificate.class);
        when(emptyCert.getEncoded()).thenReturn(new byte[0]);

        return Stream.of(Arguments.of(null, true), Arguments.of(emptyCert, true), Arguments.of(validCert, false));
    }

    @ParameterizedTest
    @MethodSource("validatePrivateKeyProvider")
    void testValidatePrivateKey(PrivateKey key, boolean shouldThrow) {
        if (shouldThrow) {
            assertThrows(IllegalArgumentException.class, () -> ValidationUtils.validatePrivateKey(key));
        } else {
            assertDoesNotThrow(() -> ValidationUtils.validatePrivateKey(key));
        }
    }

    static Stream<Arguments> validatePrivateKeyProvider() {
        PrivateKey validKey = mock(PrivateKey.class);
        when(validKey.isDestroyed()).thenReturn(false);
        when(validKey.getEncoded()).thenReturn(new byte[] {1, 2, 3});

        PrivateKey destroyedKey = mock(PrivateKey.class);
        when(destroyedKey.isDestroyed()).thenReturn(true);

        PrivateKey emptyKey = mock(PrivateKey.class);
        when(emptyKey.isDestroyed()).thenReturn(false);
        when(emptyKey.getEncoded()).thenReturn(new byte[0]);

        return Stream.of(
                Arguments.of(null, true),
                Arguments.of(destroyedKey, true),
                Arguments.of(emptyKey, false),
                Arguments.of(validKey, false));
    }

    @ParameterizedTest
    @MethodSource("validateSessionDurationProvider")
    void testValidateSessionDuration(Integer duration, boolean shouldThrow) {
        if (shouldThrow) {
            assertThrows(IllegalArgumentException.class, () -> ValidationUtils.validateSessionDuration(duration));
        } else {
            assertDoesNotThrow(() -> ValidationUtils.validateSessionDuration(duration));
        }
    }

    static Stream<Arguments> validateSessionDurationProvider() {
        return Stream.of(
                Arguments.of(null, false),
                Arguments.of(899, true),
                Arguments.of(900, false),
                Arguments.of(3600, false),
                Arguments.of(43200, false),
                Arguments.of(43201, true));
    }
}
