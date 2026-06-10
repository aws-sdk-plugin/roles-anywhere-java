package software.amazon.awssdk.services.rolesanywhere.auth;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Utility class for common validation operations used throughout the Roles
 * Anywhere authentication package.
 * Provides consistent error messages and validation logic to eliminate code
 * duplication.
 */
final class ValidationUtils {

    private ValidationUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Validates that a string parameter is not null and not empty/whitespace-only.
     *
     * @param value         The string value to validate
     * @param parameterName The name of the parameter for error messages
     * @throws IllegalArgumentException if the value is null, empty, or
     *                                  whitespace-only
     */
    static void requireNonNullAndNonEmpty(String value, String parameterName) {
        // not using nullOrEmpty for better exceptions
        if (value == null) {
            throw new IllegalArgumentException(parameterName + " is required, but was null");
        }
        if (value.trim().isEmpty()) {
            throw new IllegalArgumentException(parameterName + " cannot be empty or whitespace-only");
        }
    }

    /**
     * Validates that a required parameter is present (not null).
     *
     * @param value         The object to validate
     * @param parameterName The name of the parameter for error messages
     * @throws IllegalArgumentException if the value is null
     */
    static void requireParameter(Object value, String parameterName) {
        if (value == null) {
            throw new IllegalArgumentException(parameterName + " is required, but was null");
        }
    }

    /**
     * Identifies if a string parameter is null or empty/whitespace-only.
     *
     * @param value The string value to check
     * @return true if the value is null, empty, or whitespace-only
     */
    static boolean nullOrEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    /**
     * Identifies if a byte array is null or empty.
     *
     * @param value The byte array to check
     * @return true if the value is null or has length 0
     */
    static boolean nullOrEmpty(byte[] value) {
        return value == null || value.length == 0;
    }

    /**
     * Validates that an X509Certificate is not null and has valid encoded content.
     *
     * @param certificate The certificate to validate
     * @throws IllegalArgumentException     if the certificate is null or has no
     *                                      content
     * @throws CertificateEncodingException if the certificate cannot be encoded
     */
    static void validateCertificate(X509Certificate certificate) throws CertificateEncodingException {
        if (certificate == null || nullOrEmpty(certificate.getEncoded())) {
            throw new IllegalArgumentException("X509 Certificate cannot be null and must have contents");
        }
    }

    /**
     * Validates that a PrivateKey is not null, not destroyed, and has valid encoded
     * content.
     *
     * @param privateKey The private key to validate
     * @throws IllegalArgumentException if the private key is null, destroyed, or
     *                                  has no content
     */
    static void validatePrivateKey(PrivateKey privateKey) {
        if (privateKey == null || privateKey.isDestroyed()) {
            throw new IllegalArgumentException("Private Key cannot be null or destroyed");
        }
    }

    /**
     * Validates that a duration is within the acceptable range for
     * CreateSessionRequestBuilder.
     *
     * @param durationSeconds The duration in seconds to validate
     * @throws IllegalArgumentException if the duration is outside the valid range
     *                                  (900-43200 seconds)
     */
    static void validateSessionDuration(Integer durationSeconds) {
        if (durationSeconds != null) {
            if (durationSeconds < 900 || durationSeconds > 43200) {
                throw new IllegalArgumentException(
                        "Duration seconds must be between 900 (15 minutes) and 43200 (12 hours), got: "
                                + durationSeconds);
            }
        }
    }
}
