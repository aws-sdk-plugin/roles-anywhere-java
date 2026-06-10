package software.amazon.awssdk.services.rolesanywhere.auth;

/**
 * This X509IdentityProvider class that lets library users implement code for how
 * they want to fetch their certificates and private keys.
 */
@FunctionalInterface
public interface X509IdentityProvider {
    /**
     * Creates an X509Identity at runtime. Implementations should load the certificate
     * and private key within this method to minimize the time sensitive key material
     * is held in memory.
     *
     * @return a valid X509Identity
     * @throws IdentityProviderException if the identity cannot be created
     */
    X509Identity create() throws IdentityProviderException;
}
