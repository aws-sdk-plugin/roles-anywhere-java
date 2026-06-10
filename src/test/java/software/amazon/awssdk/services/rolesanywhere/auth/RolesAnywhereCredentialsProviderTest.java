package software.amazon.awssdk.services.rolesanywhere.auth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.regions.Region;

import java.io.ByteArrayInputStream;
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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.spy;

/**
 * Test class for RolesAnywhereCredentialsProvider.
 */
public class RolesAnywhereCredentialsProviderTest {

    // ARNs from environment variables with fallback defaults (generic test values)
    private static final String TEST_ROLE_ARN = System.getenv().getOrDefault(
            "ROLES_ANYWHERE_TEST_ROLE_ARN",
            "arn:aws:iam::123456789012:role/TestRole");
    private static final String TEST_PROFILE_ARN = System.getenv().getOrDefault(
            "ROLES_ANYWHERE_TEST_PROFILE_ARN",
            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/00000000-0000-0000-0000-000000000000");
    private static final String TEST_TRUST_ANCHOR_ARN = System.getenv().getOrDefault(
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
        when(certificate.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getIssuerX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=test"));
        when(certificate.getNotBefore()).thenReturn(new java.util.Date());
        long certNotAfter = 365L * 24 * 60 * 60 * 1000;
        when(certificate.getNotAfter()).thenReturn(new java.util.Date(System.currentTimeMillis() + certNotAfter));
        when(certificate.getSerialNumber()).thenReturn(java.math.BigInteger.ONE);
        when(certificate.getVersion()).thenReturn(3);
        when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
        when(certificate.getEncoded()).thenReturn(("-----BEGIN CERTIFICATE-----"
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
                + "\n-----END CERTIFICATE-----").getBytes(StandardCharsets.UTF_8));

        return new X509Identity(certificate, privateKey);
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
    public void testBuilderArnValidation() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test invalid trust anchor ARN
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder()
                        .identityProvider(() -> identity)
                        .trustAnchorArn("invalid-arn")
                        .profileArn(TEST_PROFILE_ARN)
                        .roleArn(TEST_ROLE_ARN)
                        .region(Region.US_EAST_1)
                        .build());
        assertEquals("Expected: "
                + "arn:<partition>:rolesanywhere:<region>:<account>:trust-anchor/<trust-anchor-id>, "
                + "but got: invalid-arn",
                exception1.getMessage());

        // Test invalid profile ARN
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder()
                        .identityProvider(() -> identity)
                        .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                        .profileArn("invalid-arn")
                        .roleArn(TEST_ROLE_ARN)
                        .region(Region.US_EAST_1)
                        .build());
        assertEquals("Expected: "
                + "arn:<partition>:rolesanywhere:<region>:<account>:profile/<profile-id>, but got: invalid-arn",
                exception2.getMessage());

        // Test invalid role ARN
        IllegalArgumentException exception3 = assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialsProvider.builder()
                        .identityProvider(() -> identity)
                        .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                        .profileArn(TEST_PROFILE_ARN)
                        .roleArn("invalid-arn")
                        .region(Region.US_EAST_1)
                        .build());
        assertEquals("Expected: arn:<partition>:iam::<account>:role/<role-name>, but got: invalid-arn",
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
        assertEquals("Duration seconds must be between 900 (15 minutes) and 43200 (12 hours), got: 300",
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
        assertEquals("Duration seconds must be between 900 (15 minutes) and 43200 (12 hours), got: 50000",
                exception2.getMessage());
    }

    @Test
    public void testResolveCredentials() throws Exception {
        // Test provider is not setup to succeed, so we will mock the HTTP response from
        // the service
        // Mock the HTTP response from the RolesAnywhere service
        String expiration = Instant.now().plus(Duration.ofMinutes(60)).toString();
        String mockResponseBody = "{"
                + "\"credentialSet\": [{"
                + "\"credentials\": {"
                + "\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\","
                + "\"secretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\","
                + "\"sessionToken\": \"AQoDYXdzEJr...<remainder of security token>\","
                + "\"expiration\": \"" + expiration + "\""
                + "},"
                + "\"roleArn\": \"" + TEST_ROLE_ARN + "\""
                + "}]"
                + "}";

        // Mock the HTTP client to return our mock response
        SdkHttpClient mockHttpClient = mock(software.amazon.awssdk.http.SdkHttpClient.class);
        ExecutableHttpRequest mockExecutableRequest = mock(software.amazon.awssdk.http.ExecutableHttpRequest.class);
        HttpExecuteResponse mockHttpResponse = mock(software.amazon.awssdk.http.HttpExecuteResponse.class);
        SdkHttpResponse mockSdkHttpResponse = mock(software.amazon.awssdk.http.SdkHttpResponse.class);

        when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
        when(mockExecutableRequest.call()).thenReturn(mockHttpResponse);
        when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
        when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
        when(mockSdkHttpResponse.statusCode()).thenReturn(201);
        when(mockHttpResponse.responseBody()).thenReturn(java.util.Optional.of(
                AbortableInputStream.create(
                        new ByteArrayInputStream(mockResponseBody.getBytes(StandardCharsets.UTF_8)))));
        // Create provider with mock HTTP client
        X509Identity identity = createTestIdentity();
        RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .httpClient(mockHttpClient)
                .build();
        AwsCredentials sessionCredentials = provider.resolveCredentials();
        assertNotNull(sessionCredentials);
        assertNotNull(sessionCredentials.accessKeyId());
        assertNotNull(sessionCredentials.secretAccessKey());
        assertEquals("AKIAIOSFODNN7EXAMPLE", sessionCredentials.accessKeyId());
    }

    @Test
    public void testEndpointConfiguration() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test with default settings
        RolesAnywhereCredentialsProvider provider0 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .build();
        assertNotNull(provider0);

        // Test that the provider can create a request builder with default endpoint
        // settings
        CreateSessionRequestBuilder builder0 = provider0.createSessionRequestBuilder();
        assertNotNull(builder0);
        SdkHttpFullRequest request0 = builder0.build();
        assertEquals("rolesanywhere.us-east-1.amazonaws.com", request0.host());

        // Test with custom endpoint
        RolesAnywhereCredentialsProvider provider1 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("https://custom.endpoint.example.com")
                .build();
        assertNotNull(provider1);

        // Test that custom endpoint is used
        CreateSessionRequestBuilder builder1 = provider1.createSessionRequestBuilder();
        assertNotNull(builder1);
        SdkHttpFullRequest request1 = builder1.build();
        assertEquals("custom.endpoint.example.com", request1.host());

        // Test with FIPS enabled
        RolesAnywhereCredentialsProvider provider2 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .fipsEnabled(true)
                .build();
        assertNotNull(provider2);

        // Test FIPS endpoint resolution
        CreateSessionRequestBuilder builder2 = provider2.createSessionRequestBuilder();
        assertNotNull(builder2);
        SdkHttpFullRequest request2 = builder2.build();
        assertEquals("rolesanywhere-fips.us-east-1.amazonaws.com", request2.host());

        // Test with dual-stack enabled
        RolesAnywhereCredentialsProvider provider3 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .dualStackEnabled(true)
                .build();
        assertNotNull(provider3);

        CreateSessionRequestBuilder builder3 = provider3.createSessionRequestBuilder();
        assertNotNull(builder3);
        SdkHttpFullRequest request3 = builder3.build();
        assertEquals("rolesanywhere.us-east-1.api.aws", request3.host());

        // Test with FIPS + dual-stack enabled (both can be used together)
        RolesAnywhereCredentialsProvider provider4 = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .dualStackEnabled(true)
                .fipsEnabled(true)
                .build();
        assertNotNull(provider4);

        CreateSessionRequestBuilder builder4 = provider4.createSessionRequestBuilder();
        assertNotNull(builder4);
        SdkHttpFullRequest request4 = builder4.build();
        assertEquals("rolesanywhere-fips.us-east-1.api.aws", request4.host());
    }

    @Test
    public void testCustomEndpointOverridesRegionFipsDualStack() throws Exception {
        X509Identity identity = createTestIdentity();

        // Test that custom endpoint overrides FIPS and dual-stack settings
        RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_WEST_2) // Different region
                .fipsEnabled(true) // FIPS enabled
                .dualStackEnabled(true) // Dual-stack enabled
                .endpoint("https://custom.endpoint.example.com") // Custom endpoint should override all
                .build();

        // Custom endpoint should be used exactly as specified, ignoring
        // region/FIPS/dual-stack
        CreateSessionRequestBuilder builder = provider.createSessionRequestBuilder();
        assertNotNull(builder);
        SdkHttpFullRequest request = builder.build();
        assertEquals("custom.endpoint.example.com", request.host());
    }

    @Test
    public void testWithRealCertificates() throws Exception {
        // This test specifically tries to use the real certificates from integration
        // testing using environment variables or defaults
        String certPathStr = System.getenv().getOrDefault(
                "ROLES_ANYWHERE_TEST_CERT_PATH",
                "src/test/resources/test-cert.pem");
        String keyPathStr = System.getenv().getOrDefault(
                "ROLES_ANYWHERE_TEST_KEY_PATH",
                "src/test/resources/test-key.pkcs8");

        Path certPath = Paths.get(certPathStr);
        Path keyPath = Paths.get(keyPathStr);

        // Skip test if certificates are not available
        if (!Files.exists(certPath) || !Files.exists(keyPath)) {
            System.out.println("Skipping real certificate test - certificates not found at:");
            System.out.println("  Certificate: " + certPath.toAbsolutePath());
            System.out.println("  Private Key: " + keyPath.toAbsolutePath());
            return;
        }

        try {
            X509Certificate certificate = CertificateUtils.loadCertificate(certPath);
            PrivateKey privateKey = CertificateUtils.loadPrivateKey(keyPath, "RSA");
            X509Identity identity = new X509Identity(certificate, privateKey);

            RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .build();

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

        } catch (Exception e) {
            System.out.println("Failed to load real certificates: " + e.getMessage());
            throw e;
        }
    }

    @Test
    public void testCaching() {
        final int calls = 5;
        Assertions.assertDoesNotThrow(() -> {
            // Setup mock objects
            String expiration = Instant.now().plus(Duration.ofHours(1)).toString();
            String mockResponseBody = "{"
                    + "\"credentialSet\": [{"
                    + "\"credentials\": {"
                    + "\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\","
                    + "\"secretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\","
                    + "\"sessionToken\": \"AQoDYXdzEJr...<remainder of security token>\","
                    + "\"expiration\": \"" + expiration + "\""
                    + "},"
                    + "\"roleArn\": \"" + TEST_ROLE_ARN + "\""
                    + "}]"
                    + "}";

            // Mock the HTTP client to return our mock response
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
            ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
            HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
            SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

            // Setup objects to test
            X509Identity identity = createTestIdentity();
            // Test that custom endpoint overrides FIPS and dual-stack settings
            RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .httpClient(mockHttpClient)
                    .build();

            // call
            for (int i = 0; i < calls; i++) {
                when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
                when(mockExecutableRequest.call()).thenReturn(mockHttpResponse);
                when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
                when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
                when(mockSdkHttpResponse.statusCode()).thenReturn(201);
                when(mockHttpResponse.responseBody()).thenReturn(Optional.of(
                        AbortableInputStream.create(
                                new ByteArrayInputStream(mockResponseBody.getBytes(StandardCharsets.UTF_8)))));
                provider.resolveCredentials();
            }

            verify(mockExecutableRequest, times(1)).call();
        });
    }

    @Test
    public void testWithoutCaching() {
        final int calls = 5;
        Assertions.assertDoesNotThrow(() -> {
            // Setup mock objects
            String expiration = Instant.now().plus(Duration.ofHours(1)).toString();
            String mockResponseBody = "{"
                    + "\"credentialSet\": [{"
                    + "\"credentials\": {"
                    + "\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\","
                    + "\"secretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\","
                    + "\"sessionToken\": \"AQoDYXdzEJr...<remainder of security token>\","
                    + "\"expiration\": \"" + expiration + "\""
                    + "},"
                    + "\"roleArn\": \"" + TEST_ROLE_ARN + "\""
                    + "}]"
                    + "}";

            // Mock the HTTP client to return our mock response
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
            ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
            HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
            SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

            // Setup objects to test
            X509Identity identity = createTestIdentity();
            // Test that custom endpoint overrides FIPS and dual-stack settings
            RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .staleTime(Duration.ofHours(1)) // ensure creds are always stale
                    .minRefreshInterval(Duration.ZERO) // allow rapid refresh for test
                    .httpClient(mockHttpClient)
                    .build();

            // call
            for (int i = 0; i < calls; i++) {
                when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
                when(mockExecutableRequest.call()).thenReturn(mockHttpResponse);
                when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
                when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
                when(mockSdkHttpResponse.statusCode()).thenReturn(201);
                when(mockHttpResponse.responseBody()).thenReturn(Optional.of(
                        AbortableInputStream.create(
                                new ByteArrayInputStream(mockResponseBody.getBytes(StandardCharsets.UTF_8)))));
                provider.resolveCredentials();
            }

            verify(mockExecutableRequest, times(calls)).call();
        });
    }

    @Test
    public void testIdentityProviderIsCalledAtResolveTime() throws Exception {
        X509IdentityProvider provider = spy(new X509IdentityProvider() {
            @Override
            public X509Identity create() {
                try {
                    return createTestIdentity();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
        ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
        HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
        SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

        String expiration = Instant.now().plus(Duration.ofHours(1)).toString();
        String mockResponseBody = "{"
                + "\"credentialSet\": [{"
                + "\"credentials\": {"
                + "\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\","
                + "\"secretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\","
                + "\"sessionToken\": \"AQoDYXdzEJr...\","
                + "\"expiration\": \"" + expiration + "\""
                + "},"
                + "\"roleArn\": \"" + TEST_ROLE_ARN + "\""
                + "}]"
                + "}";

        RolesAnywhereCredentialsProvider credentialsProvider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(provider)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .httpClient(mockHttpClient)
                .build();

        when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
        when(mockExecutableRequest.call()).thenReturn(mockHttpResponse);
        when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
        when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
        when(mockSdkHttpResponse.statusCode()).thenReturn(201);
        when(mockHttpResponse.responseBody()).thenReturn(Optional.of(
                AbortableInputStream.create(
                        new ByteArrayInputStream(mockResponseBody.getBytes(StandardCharsets.UTF_8)))));

        credentialsProvider.resolveCredentials();

        // identityProvider.create() is only called at resolveCredentials time, not at build time
        verify(provider, times(1)).create();
    }

    @Test
    public void testMinRefreshIntervalPreventsRetryStorm() {
        final int calls = 5;
        Assertions.assertDoesNotThrow(() -> {
            String expiration = Instant.now().minus(Duration.ofHours(1)).toString(); // already expired
            String mockResponseBody = "{"
                    + "\"credentialSet\": [{"
                    + "\"credentials\": {"
                    + "\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\","
                    + "\"secretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\","
                    + "\"sessionToken\": \"AQoDYXdzEJr...\","
                    + "\"expiration\": \"" + expiration + "\""
                    + "},"
                    + "\"roleArn\": \"" + TEST_ROLE_ARN + "\""
                    + "}]"
                    + "}";

            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);
            ExecutableHttpRequest mockExecutableRequest = mock(ExecutableHttpRequest.class);
            HttpExecuteResponse mockHttpResponse = mock(HttpExecuteResponse.class);
            SdkHttpResponse mockSdkHttpResponse = mock(SdkHttpResponse.class);

            X509Identity identity = createTestIdentity();
            RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .httpClient(mockHttpClient)
                    .build();

            when(mockHttpClient.prepareRequest(any())).thenReturn(mockExecutableRequest);
            when(mockExecutableRequest.call()).thenReturn(mockHttpResponse);
            when(mockHttpResponse.httpResponse()).thenReturn(mockSdkHttpResponse);
            when(mockSdkHttpResponse.isSuccessful()).thenReturn(true);
            when(mockSdkHttpResponse.statusCode()).thenReturn(201);
            when(mockHttpResponse.responseBody()).thenReturn(Optional.of(
                    AbortableInputStream.create(
                            new ByteArrayInputStream(mockResponseBody.getBytes(StandardCharsets.UTF_8)))));

            // Call multiple times rapidly — should only hit the service once
            for (int i = 0; i < calls; i++) {
                provider.resolveCredentials();
            }

            // Only 1 actual HTTP call despite expired creds, because minRefreshInterval blocks retries
            verify(mockExecutableRequest, times(1)).call();
        });
    }

    @Test
    public void testMinRefreshIntervalFloorValidation() {
        assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereCredentialsProvider.builder()
                        .minRefreshInterval(Duration.ofSeconds(10)));
    }

    @Test
    public void testMinRefreshIntervalNullValidation() {
        assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereCredentialsProvider.builder()
                        .minRefreshInterval(null));
    }

    @Test
    public void testMinRefreshIntervalCustomValue() {
        Assertions.assertDoesNotThrow(() -> {
            X509Identity identity = createTestIdentity();
            RolesAnywhereCredentialsProvider.builder()
                    .identityProvider(() -> identity)
                    .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                    .profileArn(TEST_PROFILE_ARN)
                    .roleArn(TEST_ROLE_ARN)
                    .region(Region.US_EAST_1)
                    .minRefreshInterval(Duration.ofSeconds(30))
                    .build();
        });
    }

    @Test
    public void testHttpEndpointDoesNotThrow() throws Exception {
        X509Identity identity = createTestIdentity();

        // Non-HTTPS endpoint should warn but not throw at builder time
        RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("http://localhost:8080")
                .build();
        assertNotNull(provider);
    }

    @Test
    public void testHttpEndpointViaUriDoesNotThrow() throws Exception {
        X509Identity identity = createTestIdentity();

        // Non-HTTPS endpoint via URI overload should warn but not throw
        RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint(java.net.URI.create("http://localhost:8080"))
                .build();
        assertNotNull(provider);
    }

    @Test
    public void testEndpointInvalidUriThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereCredentialsProvider.builder()
                        .endpoint("not a valid uri %%%"));
    }

    @Test
    public void testEndpointNullUnsetsEndpoint() throws Exception {
        X509Identity identity = createTestIdentity();

        // Setting null should unset and fall back to default
        RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(() -> identity)
                .trustAnchorArn(TEST_TRUST_ANCHOR_ARN)
                .profileArn(TEST_PROFILE_ARN)
                .roleArn(TEST_ROLE_ARN)
                .region(Region.US_EAST_1)
                .endpoint("https://custom.example.com")
                .endpoint((String) null)
                .build();

        CreateSessionRequestBuilder builder = provider.createSessionRequestBuilder();
        SdkHttpFullRequest request = builder.build();
        assertEquals("rolesanywhere.us-east-1.amazonaws.com", request.host());
    }
}
