package software.amazon.rolesanywhere.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.auth.spi.signer.AsyncSignRequest;
import software.amazon.awssdk.http.auth.spi.signer.AsyncSignedRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.regions.Region;

/**
 * Unit tests for X509Signer.
 */
class X509SignerTest {

    @Test
    void testPostRequestWithoutPayloadOrQueryParametersSucceeds() throws Exception {
        // Create a POST request without payload or query parameters
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .protocol("https")
                .host("rolesanywhere.us-east-1.amazonaws.com")
                .encodedPath("/sessions")
                .uri(URI.create("https://rolesanywhere.us-east-1.amazonaws.com/sessions"))
                .build();

        // Create signer
        X509Signer signer = X509Signer.builder()
                .serviceName("rolesanywhere")
                .region(Region.US_EAST_1)
                .build();

        // Generate minimal RSA key pair for test
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create mock certificate with all required methods
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getIssuerX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getNotBefore()).thenReturn(Date.from(Instant.now()));
        long certNotAfter = 365L * 24 * 60 * 60 * 1000;
        when(certificate.getNotAfter()).thenReturn(Date.from(Instant.now().plusMillis(certNotAfter)));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.ONE);
        when(certificate.getVersion()).thenReturn(3);
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
        when(certificate.getEncoded())
                .thenReturn(("-----BEGIN CERTIFICATE-----"
                                + "\nMIID7DCCAtSgAwIBAgIUHqA5luH++q9Y62QO5xUx7LiBIIkwDQYJKoZIhvcNAQEL"
                                + "\n-----END CERTIFICATE-----")
                        .getBytes(StandardCharsets.UTF_8));

        // Sign the request - should succeed without throwing exception
        SignedRequest signedRequest = signer.sign(request, keyPair.getPrivate(), certificate);

        // Verify the request was signed successfully
        assertNotNull(signedRequest, "Signed request should not be null");
        assertNotNull(signedRequest.request(), "Signed request should contain a request");
    }

    @Test
    void testUserAgentHeaderIsPresent() throws Exception {
        // Generate test key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create mock certificate
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getIssuerX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getNotBefore()).thenReturn(Date.from(Instant.now()));
        long certNotAfter = 365L * 24 * 60 * 60 * 1000;
        when(certificate.getNotAfter()).thenReturn(Date.from(Instant.now().plusMillis(certNotAfter)));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.ONE);
        when(certificate.getVersion()).thenReturn(3);
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
        when(certificate.getEncoded())
                .thenReturn(("-----BEGIN CERTIFICATE-----"
                                + "\nMIID7DCCAtSgAwIBAgIUHqA5luH++q9Y62QO5xUx7LiBIIkwDQYJKoZIhvcNAQEL"
                                + "\n-----END CERTIFICATE-----")
                        .getBytes(StandardCharsets.UTF_8));

        // Create signer
        X509Signer signer = X509Signer.builder()
                .serviceName("rolesanywhere")
                .region(Region.US_EAST_1)
                .build();

        // Create test request
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .uri(URI.create("https://rolesanywhere.us-east-1.amazonaws.com/sessions"))
                .method(SdkHttpMethod.POST)
                .build();

        // Sign the request
        SignedRequest signedRequest = signer.sign(request, keyPair.getPrivate(), certificate);

        // Verify User-Agent header is present
        List<String> userAgentHeaders = signedRequest.request().headers().get(X509Signer.USER_AGENT);
        assertNotNull(userAgentHeaders, "User-Agent header should be present");
        assertEquals(1, userAgentHeaders.size(), "Should have exactly one User-Agent header");

        String userAgent = userAgentHeaders.get(0);
        assertNotNull(userAgent, "User-Agent value should not be null");

        // Verify format: CredProvider/<version> (<javaVersion>; <os>/<osVersion>;
        // <arch>)
        // Pattern allows for flexible version, java version, os, osVersion, and arch
        // values
        Pattern userAgentPattern = Pattern.compile("^CredProvider/[^ ]+ \\([^;]+; [^;]+/[^;]+; [^)]+\\)$");
        String expectedFormat = "CredProvider/<version> (<javaVersion>; <os>/<osVersion>; <arch>)";
        assertTrue(
                userAgentPattern.matcher(userAgent).matches(),
                "User-Agent should match format '" + expectedFormat + "'. Got: " + userAgent);

        // Verify it starts with CredProvider/
        assertTrue(
                userAgent.startsWith("CredProvider/"),
                "User-Agent should start with 'CredProvider/'. Got: " + userAgent);
    }

    @Test
    void testSignAsyncEmptyPayloadReturnsCompletedFutureWithoutBlocking() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = mockCertificate(keyPair);
        X509Identity identity = new X509Identity(certificate, keyPair.getPrivate());

        X509Signer signer = X509Signer.builder()
                .serviceName("rolesanywhere")
                .region(Region.US_EAST_1)
                .build();

        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .protocol("https")
                .host("rolesanywhere.us-east-1.amazonaws.com")
                .encodedPath("/sessions")
                .uri(URI.create("https://rolesanywhere.us-east-1.amazonaws.com/sessions"))
                .build();

        AsyncSignRequest<X509Identity> asyncReq =
                AsyncSignRequest.builder(identity).request(request).build();

        CompletableFuture<AsyncSignedRequest> future = signer.signAsync(asyncReq);

        // Empty-payload path is fully synchronous — future is already complete by the
        // time signAsync returns. This is the structural proof that no thread is
        // parked waiting for a payload publisher.
        assertTrue(future.isDone(), "Empty-payload signAsync should return an already-completed future");

        AsyncSignedRequest result = future.get(1, TimeUnit.SECONDS);
        assertNotNull(result.request().firstMatchingHeader("Authorization").orElse(null));
    }

    @Test
    void testSignAsyncWithPayloadComposesOnPublisherWithoutBlocking() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = mockCertificate(keyPair);
        X509Identity identity = new X509Identity(certificate, keyPair.getPrivate());

        X509Signer signer = X509Signer.builder()
                .serviceName("rolesanywhere")
                .region(Region.US_EAST_1)
                .build();

        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .protocol("https")
                .host("rolesanywhere.us-east-1.amazonaws.com")
                .encodedPath("/sessions")
                .uri(URI.create("https://rolesanywhere.us-east-1.amazonaws.com/sessions"))
                .build();

        // Deferred publisher — emits onSubscribe immediately but doesn't deliver
        // any bytes until we manually drive it. signAsync must NOT block waiting
        // for completion.
        DeferredPublisher publisher = new DeferredPublisher();
        AsyncSignRequest<X509Identity> asyncReq = AsyncSignRequest.builder(identity)
                .request(request)
                .payload(publisher)
                .build();

        CompletableFuture<AsyncSignedRequest> future = signer.signAsync(asyncReq);

        // Future must NOT be done yet — proof that signAsync composes on the
        // publisher rather than blocking until it drains.
        assertTrue(!future.isDone(), "signAsync must not block on the publisher");

        // Now drive the publisher to completion.
        publisher.deliver("hello".getBytes(StandardCharsets.UTF_8));

        AsyncSignedRequest result = future.get(1, TimeUnit.SECONDS);
        assertNotNull(result.request().firstMatchingHeader("Authorization").orElse(null));
        assertTrue(result.payload().isPresent(), "AsyncSignedRequest should expose the signed payload");
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private static X509Certificate mockCertificate(KeyPair keyPair) throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getIssuerX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getNotBefore()).thenReturn(Date.from(Instant.now()));
        long certNotAfter = 365L * 24 * 60 * 60 * 1000;
        when(certificate.getNotAfter()).thenReturn(Date.from(Instant.now().plusMillis(certNotAfter)));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.ONE);
        when(certificate.getVersion()).thenReturn(3);
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
        when(certificate.getEncoded())
                .thenReturn(("-----BEGIN CERTIFICATE-----"
                                + "\nMIID7DCCAtSgAwIBAgIUHqA5luH++q9Y62QO5xUx7LiBIIkwDQYJKoZIhvcNAQEL"
                                + "\n-----END CERTIFICATE-----")
                        .getBytes(StandardCharsets.UTF_8));
        return certificate;
    }

    /**
     * Reactive Streams publisher that defers emission until {@link #deliver}
     * is called — used to prove that signAsync composes on the future rather
     * than blocking the caller thread waiting for the publisher to drain.
     */
    private static final class DeferredPublisher implements Publisher<ByteBuffer> {
        private Subscriber<? super ByteBuffer> subscriber;

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> s) {
            this.subscriber = s;
            s.onSubscribe(new Subscription() {
                @Override
                public void request(long n) {}

                @Override
                public void cancel() {}
            });
        }

        void deliver(byte[] payload) {
            subscriber.onNext(ByteBuffer.wrap(payload));
            subscriber.onComplete();
        }
    }
}
