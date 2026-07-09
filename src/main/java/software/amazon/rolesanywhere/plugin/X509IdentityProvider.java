package software.amazon.rolesanywhere.plugin;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.identity.spi.IdentityProvider;
import software.amazon.awssdk.identity.spi.ResolveIdentityRequest;

/**
 * Supplies {@link X509Identity} to {@link RolesAnywhereCredentialsProvider}.
 * Called once per credential refresh so that time-sensitive private key state
 * is only in memory while the signing request is being built.
 *
 * <p>Implements the AWS SDK {@link IdentityProvider} SPI so the same
 * implementation can be handed to SDK plumbing (auth schemes, resolver chains)
 * as well as this plugin. Customers only need to implement {@link #resolve()};
 * the SDK-facing {@link #resolveIdentity(ResolveIdentityRequest)} bridges to it
 * automatically.
 *
 * <p>Use one of the {@code fromFiles} factories for the common case of a
 * certificate and private key on local disk (re-read on every refresh, so
 * on-disk rotation is picked up automatically). Use {@link #ofStatic} when
 * the identity is genuinely static (tests, embedded constants). For dynamic
 * backends — Secrets Manager, Parameter Store, HSMs, PKCS#11 — implement
 * {@link #resolve()} directly.
 */
@SdkPublicApi
@FunctionalInterface
public interface X509IdentityProvider extends IdentityProvider<X509Identity> {

    /**
     * Loads and returns the X.509 identity. Invoked on every credential refresh.
     *
     * @throws SdkClientException if the identity cannot be produced
     */
    X509Identity resolve();

    @Override
    default Class<X509Identity> identityType() {
        return X509Identity.class;
    }

    /**
     * SDK bridge to {@link #resolve()}. Any {@link RuntimeException} thrown by
     * {@code resolve()} — commonly {@link SdkClientException} — is surfaced
     * through the returned future via
     * {@link CompletableFuture#completeExceptionally(Throwable)} rather than
     * thrown synchronously.
     */
    @Override
    default CompletableFuture<? extends X509Identity> resolveIdentity(ResolveIdentityRequest request) {
        try {
            return CompletableFuture.completedFuture(resolve());
        } catch (RuntimeException e) {
            CompletableFuture<X509Identity> failed = new CompletableFuture<>();
            failed.completeExceptionally(e);
            return failed;
        }
    }

    /**
     * File-on-disk provider. Re-reads {@code certificate} and {@code privateKey}
     * on every refresh, so on-disk rotation is picked up without restarting
     * the process. The private key is destroyed after each signing.
     *
     * <p>The factory itself only validates arguments; the disk I/O and parsing
     * happen inside {@link #resolve()} on every credential refresh. Failures
     * there surface as {@link SdkClientException} (see {@link #resolve()}).
     *
     * @param certificate  path to a PEM-encoded X.509 certificate
     * @param privateKey   path to a PEM-encoded PKCS#8 private key (unencrypted)
     * @param keyAlgorithm JCA algorithm name (e.g. "RSA", "EC", "EdDSA")
     * @throws NullPointerException if any argument is {@code null}.
     */
    static X509IdentityProvider fromFiles(Path certificate, Path privateKey, String keyAlgorithm) {
        return fromFiles(certificate, privateKey, keyAlgorithm, null, null);
    }

    /**
     * File-on-disk provider for a password-protected PKCS#8 key. Re-reads on
     * every refresh. The private key is destroyed after each signing.
     *
     * @param password decrypts the key on each refresh; caller retains ownership
     * @throws NullPointerException if {@code certificate}, {@code privateKey},
     *         or {@code keyAlgorithm} is {@code null}. {@link SdkClientException}
     *         is thrown from {@link #resolve()} on load/parse failure.
     */
    static X509IdentityProvider fromFiles(Path certificate, Path privateKey, String keyAlgorithm, char[] password) {
        return fromFiles(certificate, privateKey, keyAlgorithm, null, password);
    }

    /**
     * File-on-disk provider with an explicit intermediate chain file.
     *
     * @throws NullPointerException if {@code certificate}, {@code privateKey},
     *         or {@code keyAlgorithm} is {@code null}. {@link SdkClientException}
     *         is thrown from {@link #resolve()} on load/parse failure.
     */
    static X509IdentityProvider fromFiles(
            Path certificate, Path privateKey, String keyAlgorithm, Path certificateChain) {
        return fromFiles(certificate, privateKey, keyAlgorithm, certificateChain, null);
    }

    /**
     * File-on-disk provider with an explicit intermediate chain file and an
     * encrypted PKCS#8 private key.
     *
     * @throws NullPointerException if {@code certificate}, {@code privateKey},
     *         or {@code keyAlgorithm} is {@code null}. The returned provider's
     *         {@link #resolve()} throws {@link SdkClientException} if the
     *         certificate, private key, or chain cannot be read or parsed.
     */
    static X509IdentityProvider fromFiles(
            Path certificate, Path privateKey, String keyAlgorithm, Path certificateChain, char[] password) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        return () -> {
            try {
                X509Certificate leaf = CertificateUtils.loadCertificate(certificate);
                PrivateKey key = password == null
                        ? CertificateUtils.loadPrivateKey(privateKey, keyAlgorithm)
                        : CertificateUtils.loadPrivateKey(privateKey, keyAlgorithm, password);
                Collection<X509Certificate> chain = certificateChain == null
                        ? Collections.emptyList()
                        : CertificateChainLoader.load(certificateChain);
                return X509Identity.create(leaf, key, chain);
            } catch (GeneralSecurityException | java.io.IOException e) {
                throw SdkClientException.create(
                        "Failed to load X.509 identity from " + certificate + " / " + privateKey, e);
            }
        };
    }

    /**
     * Provider that always returns the same identity. Use for tests or when
     * the identity is embedded and never rotates. The private key is
     * <em>not</em> destroyed after signing, so it remains valid across every
     * refresh.
     *
     * @throws NullPointerException if {@code identity} is {@code null}.
     */
    static X509IdentityProvider ofStatic(X509Identity identity) {
        Objects.requireNonNull(identity, "identity");
        // Wrap into a caller-owned identity so the plugin does not destroy the
        // key after use — callers of ofStatic explicitly want the same object
        // reused across every refresh.
        X509Identity retained = X509Identity.createWithoutDestroyingKey(
                identity.certificate(), identity.privateKey(), identity.certificateChain());
        return () -> retained;
    }
}
