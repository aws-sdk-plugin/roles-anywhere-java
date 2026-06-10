package software.amazon.awssdk.services.rolesanywhere.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.regions.Region;

/**
 * Unit tests for CreateSessionRequestBuilder.
 */
class CreateSessionRequestBuilderTest {

    private static final String TRUST_ANCHOR_ARN_STRING =
            "arn:aws:rolesanywhere:us-east-1:" + "123456789012:trust-anchor/trust-anchor-id";
    private static final String PROFILE_ARN_STRING = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/profile-id";
    private static final String ROLE_ARN_STRING = "arn:aws:iam::123456789012:role/test-role";

    private static final Arn TRUST_ANCHOR_ARN = Arn.fromString(TRUST_ANCHOR_ARN_STRING);
    private static final Arn PROFILE_ARN = Arn.fromString(PROFILE_ARN_STRING);
    private static final Arn ROLE_ARN = Arn.fromString(ROLE_ARN_STRING);

    private static final String ROLE_SESSION_NAME = "test-session";
    private static final Integer DURATION_SECONDS = 3600;

    @Test
    void testBuildWithAllParameters() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_WEST_2)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName(ROLE_SESSION_NAME)
                .durationSeconds(DURATION_SECONDS);

        SdkHttpFullRequest request = builder.build();

        // Verify HTTP method and endpoint for different region
        assertEquals("POST", request.method().name());
        assertEquals("rolesanywhere.us-west-2.amazonaws.com", request.host());
        assertEquals("/sessions", request.encodedPath());

        // Verify headers
        assertEquals(
                "application/json", request.firstMatchingHeader("Content-Type").orElse(null));
        assertEquals(
                "rolesanywhere.us-west-2.amazonaws.com",
                request.firstMatchingHeader("Host").orElse(null));

        Map<String, List<String>> queryParams = request.rawQueryParameters();
        assertTrue(queryParams.isEmpty() || !queryParams.containsKey("trustAnchorArn"));

        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("\"trustAnchorArn\""));
        assertTrue(requestBody.contains("\"profileArn\""));
        assertTrue(requestBody.contains("\"roleArn\""));
        assertTrue(requestBody.contains("\"roleSessionName\":\"" + ROLE_SESSION_NAME + "\""));
        assertTrue(requestBody.contains("\"durationSeconds\":" + DURATION_SECONDS));
    }

    @Test
    void testBuildWithArnObjects() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN)
                .profileArn(PROFILE_ARN)
                .roleArn(ROLE_ARN);

        SdkHttpFullRequest request = builder.build();

        // Verify HTTP method and endpoint
        assertEquals("POST", request.method().name());
        assertEquals("rolesanywhere.us-east-1.amazonaws.com", request.host());
        assertEquals("/sessions", request.encodedPath());

        // Verify headers
        assertEquals(
                "application/json", request.firstMatchingHeader("Content-Type").orElse(null));
        assertEquals(
                "rolesanywhere.us-east-1.amazonaws.com",
                request.firstMatchingHeader("Host").orElse(null));

        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("\"trustAnchorArn\""));
        assertTrue(requestBody.contains("\"profileArn\""));
        assertTrue(requestBody.contains("\"roleArn\""));
    }

    @Test
    void testBuildWithArnObjectsAndAllParameters() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.EU_WEST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN)
                .profileArn(PROFILE_ARN)
                .roleArn(ROLE_ARN)
                .roleSessionName(ROLE_SESSION_NAME)
                .durationSeconds(DURATION_SECONDS);

        SdkHttpFullRequest request = builder.build();

        // Verify HTTP method and endpoint for different region
        assertEquals("POST", request.method().name());
        assertEquals("rolesanywhere.eu-west-1.amazonaws.com", request.host());
        assertEquals("/sessions", request.encodedPath());

        Map<String, List<String>> queryParams = request.rawQueryParameters();
        assertTrue(queryParams.isEmpty() || !queryParams.containsKey("trustAnchorArn"));

        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("\"trustAnchorArn\""));
        assertTrue(requestBody.contains("\"profileArn\""));
        assertTrue(requestBody.contains("\"roleArn\""));
        assertTrue(requestBody.contains("\"roleSessionName\":\"" + ROLE_SESSION_NAME + "\""));
        assertTrue(requestBody.contains("\"durationSeconds\":" + DURATION_SECONDS));
    }

    @Test
    void testBuildWithOnlyRoleSessionName() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.EU_WEST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName(ROLE_SESSION_NAME);

        SdkHttpFullRequest request = builder.build();

        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("\"roleSessionName\":\"" + ROLE_SESSION_NAME + "\""));
        assertFalse(requestBody.contains("durationSeconds"));
    }

    @Test
    void testBuildWithOnlyDurationSeconds() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.AP_SOUTHEAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .durationSeconds(DURATION_SECONDS);

        SdkHttpFullRequest request = builder.build();

        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("\"durationSeconds\":" + DURATION_SECONDS));
        assertFalse(requestBody.contains("roleSessionName"));
    }

    @Test
    void testBuildWithEmptyRoleSessionName() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName("");

        SdkHttpFullRequest request = builder.build();

        String requestBody = readRequestBody(request);
        assertFalse(requestBody.contains("roleSessionName"));
    }

    @Test
    void testBuildWithNullRoleSessionName() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName(null);

        SdkHttpFullRequest request = builder.build();

        String requestBody = readRequestBody(request);
        assertFalse(requestBody.contains("roleSessionName"));
    }

    @Test
    void testBuildWithWhitespaceRoleSessionName() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName("   ");

        SdkHttpFullRequest request = builder.build();

        String requestBody = readRequestBody(request);
        assertFalse(requestBody.contains("roleSessionName"));
    }

    @Test
    void testJsonEscaping() throws IOException {
        String roleSessionNameWithSpecialChars = "test\"session\\with\nspecial\tchars";

        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName(roleSessionNameWithSpecialChars);

        SdkHttpFullRequest request = builder.build();

        // Verify that special characters in roleSessionName are properly JSON-escaped
        // in the request body
        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("test\\\"session\\\\with\\nspecial\\tchars"));
    }

    @Test
    void testDifferentRegions() {
        // Test various AWS regions
        String[] regions = {"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ca-central-1"};

        for (String regionId : regions) {
            Region region = Region.of(regionId);
            CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(region)
                    .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                    .profileArn(PROFILE_ARN_STRING)
                    .roleArn(ROLE_ARN_STRING);

            SdkHttpFullRequest request = builder.build();

            String expectedHost = "rolesanywhere." + regionId + ".amazonaws.com";

            assertEquals(expectedHost, request.host());
            assertEquals("/sessions", request.encodedPath());
            assertEquals(expectedHost, request.firstMatchingHeader("Host").orElse(null));
        }
    }

    @Test
    void testConstructorWithNullRegion() {
        assertThrows(IllegalArgumentException.class, () -> new CreateSessionRequestBuilder(null));
    }

    @Test
    void testBuildWithMissingTrustAnchorArn() {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("Trust anchor ARN is required, but was null", exception.getMessage());
    }

    @Test
    void testBuildWithEmptyTrustAnchorArn() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1).trustAnchorArn("");
        });
        assertEquals("Trust anchor ARN cannot be empty or whitespace-only", exception.getMessage());
    }

    @Test
    void testBuildWithMissingProfileArn() {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .roleArn(ROLE_ARN_STRING);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("Profile ARN is required, but was null", exception.getMessage());
    }

    @Test
    void testBuildWithEmptyProfileArn() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1)
                    .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                    .profileArn("");
        });
        assertEquals("Profile ARN cannot be empty or whitespace-only", exception.getMessage());
    }

    @Test
    void testBuildWithMissingRoleArn() {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("Role ARN is required, but was null", exception.getMessage());
    }

    @Test
    void testBuildWithEmptyRoleArn() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1)
                    .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                    .profileArn(PROFILE_ARN_STRING)
                    .roleArn("");
        });
        assertEquals("Role ARN cannot be empty or whitespace-only", exception.getMessage());
    }

    @Test
    void testBuildWithWhitespaceTrustAnchorArn() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1).trustAnchorArn("   ");
        });
        assertEquals("Trust anchor ARN cannot be empty or whitespace-only", exception.getMessage());
    }

    @Test
    void testBuildWithWhitespaceProfileArn() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1)
                    .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                    .profileArn("   ");
        });
        assertEquals("Profile ARN cannot be empty or whitespace-only", exception.getMessage());
    }

    @Test
    void testBuildWithWhitespaceRoleArn() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1)
                    .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                    .profileArn(PROFILE_ARN_STRING)
                    .roleArn("   ");
        });
        assertEquals("Role ARN cannot be empty or whitespace-only", exception.getMessage());
    }

    @Test
    void testValidJsonFormat() throws IOException {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN_STRING)
                .profileArn(PROFILE_ARN_STRING)
                .roleArn(ROLE_ARN_STRING)
                .roleSessionName(ROLE_SESSION_NAME)
                .durationSeconds(DURATION_SECONDS);

        SdkHttpFullRequest request = builder.build();
        String requestBody = readRequestBody(request);

        // Verify it's valid JSON format (basic structure check)
        assertTrue(requestBody.startsWith("{"));
        assertTrue(requestBody.endsWith("}"));
        assertTrue(requestBody.contains("\"trustAnchorArn\""));
        assertTrue(requestBody.contains("\"profileArn\""));
        assertTrue(requestBody.contains("\"roleArn\""));
        assertTrue(requestBody.contains("\"roleSessionName\""));
        assertTrue(requestBody.contains("\"durationSeconds\""));

        Map<String, List<String>> queryParams = request.rawQueryParameters();
        assertTrue(queryParams.isEmpty() || !queryParams.containsKey("trustAnchorArn"));
    }

    @Test
    void testBuildWithNullArnObjects() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new CreateSessionRequestBuilder(Region.US_EAST_1).trustAnchorArn((Arn) null);
        });
        assertEquals("Trust anchor ARN is required, but was null", exception.getMessage());
    }

    @Test
    void testBuildWithMixedArnTypes() throws IOException {
        // Mix String and Arn object usage
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN) // Arn object
                .profileArn(PROFILE_ARN_STRING) // String
                .roleArn(ROLE_ARN); // Arn object

        SdkHttpFullRequest request = builder.build();

        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("\"trustAnchorArn\""));
        assertTrue(requestBody.contains("\"profileArn\""));
        assertTrue(requestBody.contains("\"roleArn\""));
    }

    @Test
    void testArnObjectOverridesStringValue() throws IOException {
        // Test that setting an Arn object after a String value overrides it
        String differentTrustAnchorArn = "arn:aws:rolesanywhere:us-west-2:123456789012:trust-anchor/different-id";

        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(differentTrustAnchorArn) // Set String first
                .trustAnchorArn(TRUST_ANCHOR_ARN) // Override with Arn object
                .profileArn(PROFILE_ARN)
                .roleArn(ROLE_ARN);

        SdkHttpFullRequest request = builder.build();

        // Verify request body does not contain ARNs
        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("trustAnchorArn"));
        assertTrue(requestBody.contains(TRUST_ANCHOR_ARN.toString()));
    }

    @Test
    void testStringOverridesArnObjectValue() throws IOException {
        // Test that setting a String after an Arn object overrides it
        String differentTrustAnchorArn = "arn:aws:rolesanywhere:us-west-2:123456789012:trust-anchor/different-id";

        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(Region.US_EAST_1)
                .trustAnchorArn(TRUST_ANCHOR_ARN) // Set Arn object first
                .trustAnchorArn(differentTrustAnchorArn) // Override with String
                .profileArn(PROFILE_ARN)
                .roleArn(ROLE_ARN);

        SdkHttpFullRequest request = builder.build();

        // Verify request body does not contain ARNs
        String requestBody = readRequestBody(request);
        assertTrue(requestBody.contains("trustAnchorArn"));
        assertTrue(requestBody.contains(differentTrustAnchorArn));
    }

    /**
     * Helper method to read the request body from an SdkHttpFullRequest.
     */
    private String readRequestBody(SdkHttpFullRequest request) throws IOException {
        if (request.contentStreamProvider().isEmpty()) {
            return "";
        }

        try (InputStream inputStream = request.contentStreamProvider().get().newStream();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            return outputStream.toString(StandardCharsets.UTF_8);
        }
    }
}
