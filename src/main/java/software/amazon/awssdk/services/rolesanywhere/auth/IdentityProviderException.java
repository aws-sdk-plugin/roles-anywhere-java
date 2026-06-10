package software.amazon.awssdk.services.rolesanywhere.auth;

/**
 * Checked exception thrown when an X509IdentityProvider cannot provide an identity.
 * This covers scenarios such as certificate stores being unavailable, HSM connectivity
 * failures, or expired credentials in a vault.
 */
public class IdentityProviderException extends Exception {

    public IdentityProviderException(String message) {
        super(message);
    }

    public IdentityProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
