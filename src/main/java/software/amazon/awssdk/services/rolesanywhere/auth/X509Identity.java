package software.amazon.awssdk.services.rolesanywhere.auth;

import software.amazon.awssdk.identity.spi.Identity;

import javax.annotation.Nonnull;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * An identity implementation that uses X.509 certificates for authentication.
 * This class encapsulates an X.509 certificate, its corresponding private key,
 * and an optional certificate chain for trust validation.
 */
public record X509Identity(X509Certificate certificate, PrivateKey privateKey,
        Collection<X509Certificate> certificateChain) implements Identity {
    /**
     * Creates an X509Identity with a certificate and private key, but no
     * certificate chain.
     *
     * @param certificate the X.509 certificate containing the public key and
     *                    identity information
     * @param privateKey  the private key corresponding to the certificate's public
     *                    key
     */
    public X509Identity(X509Certificate certificate, PrivateKey privateKey) {
        this(certificate, privateKey, Collections.emptyList());
    }

    /**
     * Creates an X509Identity with a certificate, private key, and certificate
     * chain.
     *
     * @param certificate      the X.509 certificate containing the public key and
     *                         identity information
     * @param privateKey       the private key corresponding to the certificate's
     *                         public key
     * @param certificateChain the certificate chain for trust validation, may be
     *                         null or empty
     */
    public X509Identity(X509Certificate certificate, PrivateKey privateKey,
            Collection<X509Certificate> certificateChain) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.certificateChain = Objects.requireNonNullElse(certificateChain, Collections.emptyList());
    }

    /**
     * Returns the certificate serial number as the identity identifier.
     *
     * @return the certificate serial number as a string
     */
    public String getIdentifier() {
        return certificate.getSerialNumber().toString();
    }

    @Override
    @Nonnull
    public String toString() {
        String serial = certificate.getSerialNumber().toString();
        return "X509Credentials{serialNumber=***"
                + serial.substring(Math.max(0, serial.length() - 4))
                + ", chainSize=" + certificateChain.size() + '}';
    }
}
