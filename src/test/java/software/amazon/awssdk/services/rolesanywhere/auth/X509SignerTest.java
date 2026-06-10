package software.amazon.awssdk.services.rolesanywhere.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
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
}
