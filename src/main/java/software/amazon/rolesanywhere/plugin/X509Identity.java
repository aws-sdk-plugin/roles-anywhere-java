package software.amazon.rolesanywhere.plugin;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.security.auth.DestroyFailedException;
import software.amazon.awssdk.annotations.Immutable;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.annotations.ThreadSafe;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.identity.spi.Identity;
import software.amazon.awssdk.utils.Logger;
import software.amazon.awssdk.utils.ToString;

/**
 * The X.509 end-entity identity used to authenticate to IAM Roles Anywhere: a
 * leaf certificate, its matching private key, and an optional intermediate
 * certificate chain.
 *
 * <p>Implements the AWS SDK {@link Identity} marker so the same value flows
 * through the SDK's identity/signer plumbing.
 *
 * <h2>Private-key ownership</h2>
 *
 * <p>Every {@code X509Identity} carries an ownership bit. When the plugin owns
 * the private key it will call {@link PrivateKey#destroy()} after each
 * {@code CreateSession} signing so JCE providers that honor
 * {@link javax.security.auth.Destroyable} (BouncyCastle, some HSM providers)
 * can zero their internal secret state. When the caller owns the private key
 * — because it is cached, HSM-backed, or shared across other signers — the
 * plugin never destroys it.
 *
 * <ul>
 *   <li>{@link #create}: plugin owns the key and will destroy it after use.
 *       This is the safe default and matches the common case of loading a key
 *       from disk, Secrets Manager, or a similar per-refresh source.</li>
 *   <li>{@link #createWithoutDestroyingKey}: caller owns the key; the plugin
 *       will never destroy it. Use this for HSM handles, PKCS#11 keys, keys
 *       shared across other signers, or any {@link PrivateKey} that must
 *       remain usable after {@code resolve()} returns.</li>
 * </ul>
 */
@SdkPublicApi
@Immutable
@ThreadSafe
@SuppressFBWarnings(
        value = "EI_EXPOSE_REP",
        justification = "X509Certificate is an abstract type with no copy constructor; callers are expected"
                + " to treat X509Identity as a short-lived signing context, not a long-lived data store")
public final class X509Identity implements Identity {
    private static final Logger LOG = Logger.loggerFor(X509Identity.class);

    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final List<X509Certificate> certificateChain;
    private final boolean ownsPrivateKey;

    private X509Identity(
            X509Certificate certificate,
            PrivateKey privateKey,
            Collection<X509Certificate> certificateChain,
            boolean ownsPrivateKey) {
        this.certificate = Objects.requireNonNull(certificate, "certificate");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        this.certificateChain = Collections.unmodifiableList(
                new ArrayList<>(certificateChain == null ? Collections.emptyList() : certificateChain));
        this.ownsPrivateKey = ownsPrivateKey;
    }

    /**
     * Creates an identity that the plugin owns. The plugin will call
     * {@link PrivateKey#destroy()} on {@code privateKey} after each
     * {@code CreateSession} signing.
     *
     * <p>This is the right choice when the private key is materialized freshly
     * for this identity (e.g. loaded from disk, decrypted from a secret store,
     * generated in-process) and is not reused elsewhere.
     */
    public static X509Identity create(X509Certificate certificate, PrivateKey privateKey) {
        return new X509Identity(certificate, privateKey, Collections.emptyList(), true);
    }

    /**
     * Creates an identity that the plugin owns, with an intermediate chain.
     * The chain is defensively copied. The plugin will call
     * {@link PrivateKey#destroy()} on {@code privateKey} after each signing.
     */
    public static X509Identity create(
            X509Certificate certificate, PrivateKey privateKey, Collection<X509Certificate> certificateChain) {
        return new X509Identity(certificate, privateKey, certificateChain, true);
    }

    /**
     * Creates an identity whose private key is owned by the caller. The plugin
     * will never destroy {@code privateKey}, so it remains usable for as long
     * as the caller keeps a reference.
     *
     * <p>Use this when the private key is an HSM/PKCS#11 handle, a key cached
     * across many refreshes, or a key shared with other JCE consumers.
     * Destroying such a key would break the next refresh (or another
     * subsystem), so ownership stays with the caller.
     */
    public static X509Identity createWithoutDestroyingKey(X509Certificate certificate, PrivateKey privateKey) {
        return new X509Identity(certificate, privateKey, Collections.emptyList(), false);
    }

    /**
     * Creates an identity whose private key is owned by the caller, with an
     * intermediate chain. The chain is defensively copied. The plugin will
     * never destroy {@code privateKey}.
     */
    public static X509Identity createWithoutDestroyingKey(
            X509Certificate certificate, PrivateKey privateKey, Collection<X509Certificate> certificateChain) {
        return new X509Identity(certificate, privateKey, certificateChain, false);
    }

    /**
     * Parses PEM-encoded certificate and private key strings into an identity.
     * Useful when key material is fetched from a secret store (Secrets Manager,
     * Parameter Store, S3) inside a {@link X509IdentityProvider#resolve()}
     * implementation.
     *
     * <p>The returned identity is plugin-owned; the private key will be
     * destroyed after signing.
     *
     * @param certificatePem PEM-encoded X.509 certificate
     * @param privateKeyPem  PEM-encoded PKCS#8 private key (unencrypted)
     * @param keyAlgorithm   JCA algorithm name (e.g. "RSA", "EC", "EdDSA")
     * @throws SdkClientException if either PEM string cannot be parsed or the
     *         key algorithm is not available in the JCE provider (wraps
     *         {@link java.security.GeneralSecurityException}).
     */
    public static X509Identity fromPem(String certificatePem, String privateKeyPem, String keyAlgorithm) {
        try {
            X509Certificate cert = CertificateUtils.readCertificateData(certificatePem);
            PrivateKey key = CertificateUtils.readPrivateKeyFromString(privateKeyPem, keyAlgorithm);
            return create(cert, key);
        } catch (GeneralSecurityException e) {
            throw SdkClientException.create("Failed to parse PEM identity material", e);
        }
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public List<X509Certificate> certificateChain() {
        return certificateChain;
    }

    /**
     * Best-effort zeroing of JCE-internal private key state. No-op when the
     * caller owns the key (constructed via {@link #createWithoutDestroyingKey})
     * or when the JCE provider does not honor
     * {@link javax.security.auth.Destroyable#destroy()} — most JDK-bundled
     * providers throw {@code DestroyFailedException} and leave the key
     * untouched; BouncyCastle honors it for many key types.
     */
    void destroyIfOwned() {
        if (!ownsPrivateKey) {
            return;
        }
        try {
            privateKey.destroy();
        } catch (DestroyFailedException | RuntimeException e) {
            LOG.debug(() -> "PrivateKey.destroy() not honored by JCE provider ("
                    + privateKey.getClass().getName() + "): " + e.getMessage());
        }
    }

    @Override
    @Nonnull
    public String toString() {
        String serial = certificate.getSerialNumber().toString();
        return ToString.builder("X509Identity")
                .add("serialNumber", "***" + serial.substring(Math.max(0, serial.length() - 4)))
                .add("chainSize", certificateChain.size())
                .build();
    }
}
