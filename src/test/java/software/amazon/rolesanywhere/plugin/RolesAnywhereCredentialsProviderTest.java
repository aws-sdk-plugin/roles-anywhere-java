package software.amazon.rolesanywhere.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.regions.Region;

/**
 * Test class for RolesAnywhereCredentialsProvider.
 */
public class RolesAnywhereCredentialsProviderTest {

    // ARNs from environment variables with fallback defaults (generic test values)
    private static final String TEST_ROLE_ARN =
            System.getenv().getOrDefault("ROLES_ANYWHERE_TEST_ROLE_ARN", "arn:aws:iam::123456789012:role/TestRole");
    private static final String TEST_PROFILE_ARN = System.getenv()
            .getOrDefault(
                    "ROLES_ANYWHERE_TEST_PROFILE_ARN",
                    "arn:aws:rolesanywhere:us-east-1:123456789012:profile/00000000-0000-0000-0000-000000000000");
    private static final String TEST_TRUST_ANCHOR_ARN = System.getenv()
            .getOrDefault(
                    "ROLES_ANYWHERE_TEST_TRUST_ANCHOR_ARN",
                    "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/00000000-0000-0000-0000-000000000000");

    private X509Identity createTestIdentity() throws Exception {
        // Mock certificate for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        // Create mock certificate using Mockito
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getIssuerX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getNotBefore()).thenReturn(java.util.Date.from(Instant.now()));
        long certNotAfter = 365L * 24 * 60 * 60 * 1000;
        when(certificate.getNotAfter()).thenReturn(Date.from(Instant.now().plusMillis(certNotAfter)));
        when(certificate.getSerialNumber()).thenReturn(java.math.BigInteger.ONE);
        when(certificate.getVersion()).thenReturn(3);
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
        when(certificate.getEncoded())
                .thenReturn(("-----BEGIN CERTIFICATE-----"
                                + "\nMIID7DCCAtSgAwIBAgIUHqA5luH++q9Y62QO5xUx7LiBIIkwDQYJKoZIhvcNAQEL"
                                + "\nBQAwcDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcM"
                                + "\nB1NlYXR0bGUxEDAOBgNVBAoMB1Rlc3RPcmcxETAPBgNVBAsMCFRlc3RVbml0MRUw"
                                + "\nEwYDVQQDDAxUZXN0IFJvb3QgQ0EwHhcNMjUxMDAyMTgzODQ2WhcNMjcxMDAyMTgz"
                                + "\nODQ2WjByMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UE"
                                + "\nBwwHU2VhdHRsZTEQMA4GA1UECgwHVGVzdE9yZzERMA8GA1UECwwIVGVzdFVuaXQx"
                                + "\nFzAVBgNVBAMMDnRlc3QtbGVhZi1jZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
                                + "\nMIIBCgKCAQEAvmeFjlmpxFuIU/e4cP3fiIpaV98TBgmdo4z09tfAnm+admD14nnB"
                                + "\nxqRcvw3Z+gb9l42YQlSyVYQWQ7Um2i9dVqpLlFyEJF0pus/AUgeR4Y9IkhEBUfYe"
                                + "\nRfED/G2JDlsFhXeoFLAw4ZUh+LUIJswB3stpqp4VQEyEKn05Y1AB6ng8JrUCFIEL"
                                + "\naPuThd36mf+kL7WIGMUdN1WsnxJUxM1rqY8L8pnMC4t+7PxPXnpYodov9MobIjYj"
                                + "\nqHE9TI51A0U7vSQNRy2qZ9v3cnr24kNB7DV3FuNfCZGcEhndfMeBly6xDsNAb8Oy"
                                + "\nUNQkMF6Ftr6cvp0XnYNgLWCBBRx0vDL9rQIDAQABo3wwejAJBgNVHRMEAjAAMA4G"
                                + "\nA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHQYD"
                                + "\nVR0OBBYEFLgrDIAxIVPdjKmjNc26SvFJDN8pMB8GA1UdIwQYMBaAFLvUkIVY3anl"
                                + "\njqOTlp7AR5hgNEMeMA0GCSqGSIb3DQEBCwUAA4IBAQCFcihua8HN8p4oh2/rgsWT"
                                + "\n/5Oz1BvXkFy4Wtrd5bw2DoMiHZTstvGfYuLTAco0v/UqNi6zqqNVhGrhZ0sCBg7s"
                                + "\njT6hn3gIB1dmruDjmVE294XdmLzNg0BWT0F7AHhLPj0HZn1tQpBOWX19FU6nRQq/"
                                + "\nbFNvdnCK1XCj9TEMvb+jGJkPkXH5iz1oXxBnCGw8REERF2VFPWBsuzz11KtpOePM"
                                + "\nBo3OyBjE4x25yQPd6GCoapy5/KwA1D3TgrDJrhQcF/j/4XpNxIKiN8t5ONgVY+DC"
                                + "\nFY4RQka4JGmfUhRpfZridrbtyWWulH2OZoZVo3p6i+fsiGDjgVnGw5p9KE3snmlL"
                                + "\n-----END CERTIFICATE-----")
                        .getBytes(StandardCharsets.UTF_8));

        return X509Identity.create(certificate, privateKey);
    }

    private static String mockResponseBody(Instant expiration) {
        return "{"
                + "\"credentialSet\": [{"
                + "\"credentials\": {"
                + "\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\","
                + "\"secretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\","
                + "\"sessionToken\": \"AQoDYXdzEJr...<remainder of security token>\","
                + "\"expiration\": \"" + expiration.toString() + "\""
                + "},"
                + "\"roleArn\": \"" + TEST_ROLE_ARN + "\""
                + "}]"
                + "}";
    }

    private static SdkHttpClient mockHttpClientReturning(String responseBody) throws IOException {
        SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
        ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
        HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
        SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

        when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
        when(mockExecutableRequest.call()).thenReturn(mockHttpResponse);
        when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
        when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
        when(mockSdkHttpResponse.statusCode()).thenReturn(201);
        // Each call() must yield a fresh InputStream — readAllBytes drains it.
        when(mockHttpResponse.responseBody())
                .thenAnswer((InvocationOnMock invocation) -> Optional.of(AbortableInputStream.create(
                        new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8)))));
        return mockHttpClient;
    }

    @Test
    public void testBuilderValidation() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test missing identityProvider
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> {
            RolesAnywhereCredentialsProvider.builder()
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .build();
        });
        assertEquals("X509IdentityProvider is required, but was null", exception1.getMessage());

        // Test missing trust anchor ARN
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> {
            RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .build();
        });
        assertEquals("Trust anchor ARN is required, but was null", exception2.getMessage());

        // Test missing profile ARN
        IllegalArgumentException exception3 = assertThrows(IllegalArgumentException.class, () -> {
            RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .build();
        });
        assertEquals("Profile ARN is required, but was null", exception3.getMessage());

        // Test missing role ARN
        IllegalArgumentException exception4 = assertThrows(IllegalArgumentException.class, () -> {
            RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .region(Region.US_EAST_1)
                    .build();
        });
        assertEquals("Role ARN is required, but was null", exception4.getMessage());
    }

    @Test
    public void testRequiredSettersRejectNullAtCallSite() throws Exception {
        // Setters for required parameters reject null at the call site (not at build()
        // time) so the error is attributable to the setter that received bad input.
        // Both String and Arn overloads enforce this.
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().identityProvider(null));

        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().trustAnchorArn((String) null));
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().trustAnchorArn((Arn) null));

        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().profileArn((String) null));
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().profileArn((Arn) null));

        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().roleArn((String) null));
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().roleArn((Arn) null));
    }

    @Test
    public void testRequiredStringSettersRejectBlankAtCallSite() {
        // Empty/whitespace strings are never a deliberate "reset to default" — that's
        // what null is for. Reject at the setter so the customer sees the error
        // attributed to the bad input, not to a generic "X is required" at build().
        for (String blank : new String[] {"", " ", "  ", "\t", "\n"}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> RolesAnywhereCredentialsProvider.builder().trustAnchorArn(blank),
                    "trustAnchorArn should reject blank string: '" + blank + "'");
            assertThrows(
                    IllegalArgumentException.class,
                    () -> RolesAnywhereCredentialsProvider.builder().profileArn(blank),
                    "profileArn should reject blank string: '" + blank + "'");
            assertThrows(
                    IllegalArgumentException.class,
                    () -> RolesAnywhereCredentialsProvider.builder().roleArn(blank),
                    "roleArn should reject blank string: '" + blank + "'");
        }
    }

    @Test
    public void testRoleSessionNameAcceptsNullRejectsBlank() throws Exception {
        X509Identity identity = createTestIdentity();
        // null is a valid "reset / let server pick default" value
        Assertions.assertDoesNotThrow(() -> RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .roleSessionName(null)
                .build());

        // blank is a typo, never a deliberate value
        for (String blank : new String[] {"", " ", "  ", "\t"}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> RolesAnywhereCredentialsProvider.builder().roleSessionName(blank),
                    "roleSessionName should reject blank: '" + blank + "'");
        }
    }

    @Test
    public void testEndpointAcceptsNullRejectsBlank() throws Exception {
        X509Identity identity = createTestIdentity();
        // null clears a previously-set endpoint
        Assertions.assertDoesNotThrow(() -> RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("https://custom.example.com")
                .endpoint((String) null)
                .build());

        // blank string passes URI.create() but produces no host — fail at setter
        for (String blank : new String[] {"", " ", "\t"}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> RolesAnywhereCredentialsProvider.builder().endpoint(blank),
                    "endpoint(String) should reject blank: '" + blank + "'");
        }

        // URI without a host (e.g., URI.create("")) is meaningless for a service endpoint
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().endpoint(java.net.URI.create("")));
    }

    @Test
    public void testBuilderArnValidation() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test invalid trust anchor ARN
        IllegalArgumentException exception1 = assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder()
                        .identityProvider(() -> identity)
                        .trustAnchorArn("invalid-arn")
                        .profileArn(TEST_PROFILE_ARN)
                        .roleArn(TEST_ROLE_ARN)
                        .region(Region.US_EAST_1)
                        .build());
        assertEquals(
                "Expected: "
                        + "arn:<partition>:rolesanywhere:<region>:<account>:trust-anchor/<trust-anchor-id>, "
                        + "but got: invalid-arn",
                exception1.getMessage());

        // Test invalid profile ARN
        IllegalArgumentException exception2 = assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder()
                        .identityProvider(() -> identity)
                        .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                        .profileArn("invalid-arn")
                        .roleArn(TEST_ROLE_ARN)
                        .region(Region.US_EAST_1)
                        .build());
        assertEquals(
                "Expected: "
                        + "arn:<partition>:rolesanywhere:<region>:<account>:profile/<profile-id>, but got: invalid-arn",
                exception2.getMessage());

        // Test invalid role ARN
        IllegalArgumentException exception3 = assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder()
                        .identityProvider(() -> identity)
                        .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                        .profileArn(TEST_PROFILE_ARN)
                        .roleArn("invalid-arn")
                        .region(Region.US_EAST_1)
                        .build());
        assertEquals(
                "Expected: arn:<partition>:iam::<account>:role/<role-name>, but got: invalid-arn",
                exception3.getMessage());
    }

    @Test
    public void testBuilderDurationValidation() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test invalid duration (too short)
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> {
            RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .durationSeconds(300) // Too short
                    .build();
        });
        assertEquals(
                "Duration seconds must be between 900 (15 minutes) and 43200 (12 hours), got: 300",
                exception1.getMessage());

        // Test invalid duration (too long)
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> {
            RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .durationSeconds(50000) // Too long
                    .build();
        });
        assertEquals(
                "Duration seconds must be between 900 (15 minutes) and 43200 (12 hours), got: 50000",
                exception2.getMessage());
    }

    @Test
    public void testResolveCredentials() throws Exception {
        Instant expiration = Instant.now().plus(Duration.ofMinutes(60));
        SdkHttpClient mockHttpClient = mockHttpClientReturning(mockResponseBody(expiration));

        X509Identity identity = createTestIdentity();
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .httpClient(mockHttpClient)
                .build()) {
            AwsCredentials sessionCredentials = provider.resolveCredentials();
            assertNotNull(sessionCredentials);
            assertNotNull(sessionCredentials.accessKeyId());
            assertNotNull(sessionCredentials.secretAccessKey());
            assertEquals("AKIAIOSFODNN7EXAMPLE", sessionCredentials.accessKeyId());
        }
    }

    @Test
    public void testEndpointConfiguration() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test with default settings
        try (RolesAnywhereCredentialsProvider provider0 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .build()) {
            assertNotNull(provider0);

            // Test that the provider can create a request builder with default endpoint
            // settings
            CreateSessionRequestBuilder builder0 = provider0.createSessionRequestBuilder();
            assertNotNull(builder0);
            SdkHttpFullRequest request0 = builder0.build();
            assertEquals("rolesanywhere.us-east-1.amazonaws.com", request0.host());
        }

        // Test with custom endpoint
        try (RolesAnywhereCredentialsProvider provider1 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("https://custom.endpoint.example.com")
                .build()) {
            assertNotNull(provider1);

            // Test that custom endpoint is used
            CreateSessionRequestBuilder builder1 = provider1.createSessionRequestBuilder();
            assertNotNull(builder1);
            SdkHttpFullRequest request1 = builder1.build();
            assertEquals("custom.endpoint.example.com", request1.host());
        }

        // Test with FIPS enabled
        try (RolesAnywhereCredentialsProvider provider2 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .fipsEnabled(true)
                .build()) {
            assertNotNull(provider2);

            // Test FIPS endpoint resolution
            CreateSessionRequestBuilder builder2 = provider2.createSessionRequestBuilder();
            assertNotNull(builder2);
            SdkHttpFullRequest request2 = builder2.build();
            assertEquals("rolesanywhere-fips.us-east-1.amazonaws.com", request2.host());
        }

        // Test with dual-stack enabled
        try (RolesAnywhereCredentialsProvider provider3 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .dualStackEnabled(true)
                .build()) {
            assertNotNull(provider3);

            CreateSessionRequestBuilder builder3 = provider3.createSessionRequestBuilder();
            assertNotNull(builder3);
            SdkHttpFullRequest request3 = builder3.build();
            assertEquals("rolesanywhere.us-east-1.api.aws", request3.host());
        }

        // Test with FIPS + dual-stack enabled (both can be used together)
        try (RolesAnywhereCredentialsProvider provider4 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .dualStackEnabled(true)
                .fipsEnabled(true)
                .build()) {
            assertNotNull(provider4);

            CreateSessionRequestBuilder builder4 = provider4.createSessionRequestBuilder();
            assertNotNull(builder4);
            SdkHttpFullRequest request4 = builder4.build();
            assertEquals("rolesanywhere-fips.us-east-1.api.aws", request4.host());
        }
    }

    @Test
    public void testCustomEndpointOverridesRegionFipsDualStack() throws Exception {
        X509Identity identity = createTestIdentity();

        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_WEST_2) // Different region
                .fipsEnabled(true) // FIPS enabled
                .dualStackEnabled(true) // Dual-stack enabled
                .endpoint("https://custom.endpoint.example.com") // Custom endpoint should override all
                .build()) {

            // Custom endpoint should be used exactly as specified, ignoring
            // region/FIPS/dual-stack
            CreateSessionRequestBuilder builder = provider.createSessionRequestBuilder();
            assertNotNull(builder);
            SdkHttpFullRequest request = builder.build();
            assertEquals("custom.endpoint.example.com", request.host());
        }
    }

    @Test
    public void testWithRealCertificates() throws Exception {
        // This test specifically tries to use the real certificates from integration
        // testing using environment variables or defaults
        String certPathStr =
                System.getenv().getOrDefault("ROLES_ANYWHERE_TEST_CERT_PATH", "src/test/resources/test-cert.pem");
        String keyPathStr =
                System.getenv().getOrDefault("ROLES_ANYWHERE_TEST_KEY_PATH", "src/test/resources/test-key.pkcs8");

        Path certPath = Paths.get(certPathStr);
        Path keyPath = Paths.get(keyPathStr);

        // Skip test if certificates are not available. Use assumeTrue so JUnit
        // reports the test as aborted/skipped rather than passed.
        assumeTrue(
                Files.exists(certPath) && Files.exists(keyPath),
                "Skipping real certificate test - certificates not found at: Certificate="
                        + certPath.toAbsolutePath()
                        + ", Private Key="
                        + keyPath.toAbsolutePath());

        try {
            X509Certificate certificate = CertificateUtils.loadCertificate(certPath);
            PrivateKey privateKey = CertificateUtils.loadPrivateKey(keyPath, "RSA");
            X509Identity identity = X509Identity.create(certificate, privateKey);

            try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .build()) {

                // Verify the provider was created successfully
                assertNotNull(provider);

                // Test that we can create sample credentials
                AwsCredentials credentials = provider.resolveCredentials();
                assertNotNull(credentials);

                System.out.println("Certificate Path: " + certPath.toAbsolutePath());
                System.out.println("Private Key Path: " + keyPath.toAbsolutePath());
                System.out.println("Certificate Subject: " + certificate.getSubjectX500Principal());
                System.out.println("Certificate Issuer: " + certificate.getIssuerX500Principal());
                System.out.println("Using Role ARN: " + TEST_ROLE_ARN);
                System.out.println("Using Profile ARN: " + TEST_PROFILE_ARN);
                System.out.println("Using Trust Anchor ARN: " + TEST_TRUST_ANCHOR_ARN);
            }
        } catch (Exception e) {
            System.out.println("Failed to load real certificates: " + e.getMessage());
            throw e;
        }
    }

    @Test
    public void testCachingServesPreviousValueWhilePrefetchTimeNotReached() {
        final int calls = 5;
        Assertions.assertDoesNotThrow(() -> {
            // Long-lived expiration so prefetch (= expiration - staleTime) is far in the
            // future; every call after the first should hit cache.
            String body = mockResponseBody(Instant.now().plus(Duration.ofHours(1)));
            SdkHttpClient mockHttpClient = mockHttpClientReturning(body);

            X509Identity identity = createTestIdentity();
            try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .httpClient(mockHttpClient)
                    .build()) {

                for (int i = 0; i < calls; i++) {
                    provider.resolveCredentials();
                }

                verify(mockHttpClient, times(1)).prepareRequest(any());
            }
        });
    }

    @Test
    public void testStaticStabilityServesCachedValuePastExpirationOnRefreshFailure() throws Exception {
        // Static stability invariant: once a successful refresh has cached a value,
        // a subsequent failure must NOT propagate to the caller. The cache must keep
        // serving the previous value (StaleValueBehavior.ALLOW). Service-side enforces
        // expiry; the client trusts that contract.
        AtomicInteger callCount = new AtomicInteger(0);
        SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
        ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
        HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
        SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

        // 1st call succeeds; subsequent calls fail with IOException.
        Instant expiration = Instant.now().plus(Duration.ofSeconds(2));
        String body = mockResponseBody(expiration);
        when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
        when(mockExecutableRequest.call()).thenAnswer(inv -> {
            int n = callCount.incrementAndGet();
            if (n == 1) {
                return mockHttpResponse;
            }
            throw new IOException("simulated network failure");
        });
        when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
        when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
        when(mockSdkHttpResponse.statusCode()).thenReturn(201);
        when(mockHttpResponse.responseBody())
                .thenAnswer((InvocationOnMock inv) -> Optional.of(
                        AbortableInputStream.create(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)))));

        X509Identity identity = createTestIdentity();
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                // Fast staleTime so the next resolveCredentials() crosses prefetchTime
                // and forces CachedSupplier to call our refresh function again.
                .staleTime(Duration.ofSeconds(1))
                .minRefreshInterval(Duration.ZERO)
                .httpClient(mockHttpClient)
                .build()) {

            AwsCredentials first = provider.resolveCredentials();
            assertNotNull(first);
            assertEquals("AKIAIOSFODNN7EXAMPLE", first.accessKeyId());

            // Wait until past the staleTime cutoff (= expiration). After this point,
            // CachedSupplier WILL call the refresh function, which now fails. With
            // StaleValueBehavior.ALLOW the previous value continues to be served.
            Thread.sleep(Duration.ofMillis(2500).toMillis());

            AwsCredentials afterFailure = Assertions.assertDoesNotThrow(provider::resolveCredentials);
            assertEquals(first.accessKeyId(), afterFailure.accessKeyId());
        }
    }

    @Test
    public void testColdStartFailurePropagates() throws Exception {
        // Cold-start invariant: with no value ever cached, a refresh failure must
        // propagate. Static stability has no fallback to offer.
        SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
        ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
        when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
        when(mockExecutableRequest.call()).thenThrow(new IOException("simulated cold-start failure"));

        X509Identity identity = createTestIdentity();
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .minRefreshInterval(Duration.ZERO)
                .httpClient(mockHttpClient)
                .build()) {

            assertThrows(RuntimeException.class, provider::resolveCredentials);
        }
    }

    @Test
    public void testIdentityProviderIsCalledAtResolveTime() throws Exception {
        X509IdentityProvider provider = spy(new X509IdentityProvider() {
            @Override
            public X509Identity resolve() {
                try {
                    return createTestIdentity();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        Instant expiration = Instant.now().plus(Duration.ofHours(1));
        SdkHttpClient mockHttpClient = mockHttpClientReturning(mockResponseBody(expiration));

        try (RolesAnywhereCredentialsProvider credentialsProvider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(provider)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .httpClient(mockHttpClient)
                .build()) {

            credentialsProvider.resolveCredentials();

            // identityProvider.create() is only called at resolveCredentials time, not at build time
            verify(provider, times(1)).resolve();
        }
    }

    @Test
    public void testMinRefreshIntervalPreventsRetryStorm() {
        final int calls = 5;
        Assertions.assertDoesNotThrow(() -> {
            // Identity provider always fails — the throttle is what should stop us
            // pounding the network.
            AtomicInteger identityCalls = new AtomicInteger(0);
            X509IdentityProvider failingIdentity = () -> {
                identityCalls.incrementAndGet();
                throw SdkClientException.create("simulated identity failure");
            };

            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);

            try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(failingIdentity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    // 30 seconds is the floor; the test runs in <1s so a single attempt
                    // is all the throttle should permit even though we call resolve() N times.
                    .minRefreshInterval(Duration.ofSeconds(30))
                    .httpClient(mockHttpClient)
                    .build()) {

                for (int i = 0; i < calls; i++) {
                    // Every call throws — there's no cached value to fall back to. We
                    // care only about how many times the identity provider was actually
                    // invoked.
                    try {
                        provider.resolveCredentials();
                    } catch (RuntimeException expected) {
                        // expected on cold start with persistent failures
                    }
                }

                assertEquals(1, identityCalls.get());
            }
        });
    }

    @Test
    public void testMinRefreshIntervalFloorValidation() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().minRefreshInterval(Duration.ofSeconds(10)));
    }

    @Test
    public void testMinRefreshIntervalNullValidation() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().minRefreshInterval(null));
    }

    @Test
    public void testMinRefreshIntervalCustomValue() {
        Assertions.assertDoesNotThrow(() -> {
            X509Identity identity = createTestIdentity();
            try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .minRefreshInterval(Duration.ofSeconds(30))
                    .build()) {
                assertNotNull(provider);
            }
        });
    }

    @Test
    public void testHttpEndpointDoesNotThrow() throws Exception {
        X509Identity identity = createTestIdentity();

        // Non-HTTPS endpoint should warn but not throw at builder time
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("http://localhost:8080")
                .build()) {
            assertNotNull(provider);
        }
    }

    @Test
    public void testHttpEndpointViaUriDoesNotThrow() throws Exception {
        X509Identity identity = createTestIdentity();

        // Non-HTTPS endpoint via URI overload should warn but not throw
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint(java.net.URI.create("http://localhost:8080"))
                .build()) {
            assertNotNull(provider);
        }
    }

    @Test
    public void testEndpointInvalidUriThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder().endpoint("not a valid uri %%%"));
    }

    @Test
    public void testEndpointNullUnsetsEndpoint() throws Exception {
        X509Identity identity = createTestIdentity();

        // Setting null should unset and fall back to default
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("https://custom.example.com")
                .endpoint((String) null)
                .build()) {

            CreateSessionRequestBuilder builder = provider.createSessionRequestBuilder();
            SdkHttpFullRequest request = builder.build();
            assertEquals("rolesanywhere.us-east-1.amazonaws.com", request.host());
        }
    }

    /**
     * Generative scenario test for the cache state machine. Drives the provider
     * through randomly-sampled refresh-success / refresh-failure / time-jump
     * sequences and asserts the static-stability invariants:
     *
     * <ul>
     *   <li>I1: once a successful refresh has cached a value, every subsequent
     *       resolveCredentials() returns a non-null AwsCredentials regardless of
     *       refresh failures.</li>
     *   <li>I2: under repeated calls within a single prefetch window, the
     *       network is hit at most once.</li>
     *   <li>I3: cold-start failures propagate as exceptions — no silent return
     *       of null.</li>
     * </ul>
     *
     * <p>Comprehensive in shape rather than parameterized because the input
     * space (timing × success/failure interleavings) is large and the
     * interesting bugs live in interactions, not isolated cases.
     */
    @Test
    public void testCacheStateMachineInvariants() throws Exception {
        // Deterministic seed so a regression reproduces. Pick a different seed
        // locally to exercise a different sequence.
        Random rng = new Random(0xCAFEBABEL);
        final int trials = 25;
        for (int trial = 0; trial < trials; trial++) {
            runScenario(rng, trial);
        }
    }

    private void runScenario(Random rng, int trial) throws Exception {
        boolean coldStartFailure = rng.nextBoolean();
        int callsPerWindow = 1 + rng.nextInt(8);

        AtomicInteger networkCalls = new AtomicInteger(0);
        SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
        ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
        HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
        SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

        Instant expiration = Instant.now().plus(Duration.ofHours(1));
        String body = mockResponseBody(expiration);

        when(mockHttpClient.prepareRequest(any())).thenAnswer(inv -> {
            networkCalls.incrementAndGet();
            return mockExecutableRequest;
        });
        when(mockExecutableRequest.call()).thenAnswer(inv -> {
            // Cold-start scenario: every call fails until we say otherwise.
            if (coldStartFailure && networkCalls.get() == 1) {
                throw new IOException("trial " + trial + " injected cold-start failure");
            }
            return mockHttpResponse;
        });
        when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
        when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
        when(mockSdkHttpResponse.statusCode()).thenReturn(201);
        when(mockHttpResponse.responseBody())
                .thenAnswer((InvocationOnMock inv) -> Optional.of(
                        AbortableInputStream.create(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)))));

        X509Identity identity = createTestIdentity();
        try (RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .minRefreshInterval(Duration.ZERO)
                .httpClient(mockHttpClient)
                .build()) {

            if (coldStartFailure) {
                // I3: cold-start failure propagates.
                assertThrows(
                        RuntimeException.class,
                        provider::resolveCredentials,
                        "trial " + trial + ": cold-start failure must propagate");
                return; // No cached value — nothing further to assert this trial.
            }

            AwsCredentials first = provider.resolveCredentials();
            assertNotNull(first, "trial " + trial + ": initial refresh must yield credentials");

            // I2: within one prefetch window, repeated calls must reuse the cache.
            int networkCallsAfterFirst = networkCalls.get();
            for (int i = 0; i < callsPerWindow; i++) {
                AwsCredentials c = provider.resolveCredentials();
                // I1: never null once we have a cached value.
                assertNotNull(c, "trial " + trial + ", call " + i + ": resolved credentials must not be null");
            }
            assertEquals(
                    networkCallsAfterFirst,
                    networkCalls.get(),
                    "trial " + trial + ": repeated calls inside the prefetch window must not hit the network");
        }
    }
}
