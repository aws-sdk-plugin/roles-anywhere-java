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
    void testResolveVersionMatchesGradleProjectVersion() throws Exception {
        // Gradle writes the resolved project.version into
        // META-INF/rolesanywhere-plugin-version.properties (see build.gradle.kts).
        // X509Signer.resolveVersion() reads that file at runtime so the User-Agent
        // reports a real version, not the "unknown" fallback.
        String resolved = X509Signer.resolveVersion();

        assertNotNull(resolved, "resolveVersion() must never return null");
        assertEquals(
                "unknown".equals(resolved),
                false,
                "Version resource missing — build.gradle.kts should generate META-INF/rolesanywhere-plugin-version.properties");

        // Cross-check against the same resource, loaded independently, to prove
        // resolveVersion() actually parses the file rather than pulling from
        // some other source (e.g. jar manifest, hardcoded string).
        try (java.io.InputStream in =
                X509SignerTest.class.getResourceAsStream("/META-INF/rolesanywhere-plugin-version.properties")) {
            assertNotNull(in, "Version resource must be present on the test classpath");
            java.util.Properties props = new java.util.Properties();
            props.load(in);
            assertEquals(props.getProperty("version"), resolved);
        }

        // Semantic-version-ish shape: at minimum, contains a digit and no whitespace.
        assertTrue(resolved.matches("\\S+"), "Version must not contain whitespace, got: " + resolved);
        assertTrue(resolved.matches(".*\\d.*"), "Version must contain at least one digit, got: " + resolved);
    }

    @Test
    void testUserAgentEmbedsResolvedVersion() throws Exception {
        String resolved = X509Signer.resolveVersion();
        String userAgent = signAndReadUserAgent(null);

        // Extract <ver> from RolesAnywhereJava/provider/<ver> ( ...
        Pattern extractor = Pattern.compile("^RolesAnywhereJava/provider/([^ ]+) \\(.*\\)$");
        java.util.regex.Matcher m = extractor.matcher(userAgent);
        assertTrue(m.matches(), "User-Agent should match extractor pattern. Got: " + userAgent);
        assertEquals(resolved, m.group(1), "User-Agent version segment must equal resolveVersion()");
    }

    @Test
    void testUserAgentHeaderProviderVariant() throws Exception {
        String userAgent = signAndReadUserAgent(null);

        // Format: RolesAnywhereJava/<variant>/<version> (<javaVersion>; <os>/<osVersion>; <arch>)
        Pattern userAgentPattern =
                Pattern.compile("^RolesAnywhereJava/provider/[^ ]+ \\([^;]+; [^;]+/[^;]+; [^)]+\\)$");
        assertTrue(
                userAgentPattern.matcher(userAgent).matches(),
                "User-Agent should match RolesAnywhereJava/provider/<ver> (env). Got: " + userAgent);
        assertTrue(
                userAgent.startsWith("RolesAnywhereJava/provider/"),
                "User-Agent should start with 'RolesAnywhereJava/provider/'. Got: " + userAgent);
    }

    @Test
    void testUserAgentHeaderPluginVariant() throws Exception {
        String userAgent = signAndReadUserAgent(X509Signer.Source.PLUGIN);

        Pattern userAgentPattern = Pattern.compile("^RolesAnywhereJava/plugin/[^ ]+ \\([^;]+; [^;]+/[^;]+; [^)]+\\)$");
        assertTrue(
                userAgentPattern.matcher(userAgent).matches(),
                "User-Agent should match RolesAnywhereJava/plugin/<ver> (env). Got: " + userAgent);
        assertTrue(
                userAgent.startsWith("RolesAnywhereJava/plugin/"),
                "User-Agent should start with 'RolesAnywhereJava/plugin/'. Got: " + userAgent);
    }

    private static String signAndReadUserAgent(X509Signer.Source source) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = mockCertificate(keyPair);

        X509Signer.Builder signerBuilder =
                X509Signer.builder().serviceName("rolesanywhere").region(Region.US_EAST_1);
        if (source != null) {
            signerBuilder.source(source);
        }
        X509Signer signer = signerBuilder.build();

        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .uri(URI.create("https://rolesanywhere.us-east-1.amazonaws.com/sessions"))
                .method(SdkHttpMethod.POST)
                .build();

        SignedRequest signedRequest = signer.sign(request, keyPair.getPrivate(), certificate);

        List<String> userAgentHeaders = signedRequest.request().headers().get(X509Signer.USER_AGENT);
        assertNotNull(userAgentHeaders, "User-Agent header should be present");
        assertEquals(1, userAgentHeaders.size(), "Should have exactly one User-Agent header");
        String userAgent = userAgentHeaders.get(0);
        assertNotNull(userAgent, "User-Agent value should not be null");
        return userAgent;
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
