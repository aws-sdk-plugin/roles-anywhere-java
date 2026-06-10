package software.amazon.awssdk.services.rolesanywhere.auth;

import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.endpoints.Endpoint;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rolesanywhere.endpoints.RolesAnywhereEndpointParams;
import software.amazon.awssdk.services.rolesanywhere.endpoints.RolesAnywhereEndpointProvider;
import software.amazon.awssdk.utils.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for building CreateSession API requests for IAM Roles Anywhere. This class
 * constructs properly formatted HTTP requests for the /sessions endpoint.
 */
final class CreateSessionRequestBuilder {
    private static final String CONTENT_TYPE_JSON = "application/json";

    private Arn trustAnchorArn;
    private Arn profileArn;
    private Arn roleArn;
    private String roleSessionName;
    private Integer durationSeconds;

    // Endpoint resolution settings
    private Region region;
    private URI customEndpoint;
    private boolean fipsEnabled = false;
    private boolean dualStackEnabled = false;
    private final RolesAnywhereEndpointProvider endpointProvider =
            RolesAnywhereEndpointProvider.defaultProvider();

    /**
     * Creates a new CreateSessionRequestBuilder for the specified region.
     *
     * @param region The AWS region
     * @throws IllegalArgumentException if region is null
     */
    CreateSessionRequestBuilder(Region region) {
        ValidationUtils.requireParameter(region, "Region");
        this.region = region;
    }

    /**
     * Sets the trust anchor ARN.
     *
     * @param trustAnchorArn The ARN string of the trust anchor
     * @return This builder instance
     * @throws IllegalArgumentException if the ARN format is invalid or empty
     */
    CreateSessionRequestBuilder trustAnchorArn(String trustAnchorArn) {
        ValidationUtils.requireNonNullAndNonEmpty(trustAnchorArn, "Trust anchor ARN");
        this.trustAnchorArn = ArnValidator.validateTrustAnchorArn(trustAnchorArn);
        return this;
    }

    /**
     * Sets the trust anchor ARN.
     *
     * @param trustAnchorArn The Arn object of the trust anchor
     * @return This builder instance
     * @throws IllegalArgumentException if the ARN is null
     */
    CreateSessionRequestBuilder trustAnchorArn(Arn trustAnchorArn) {
        ValidationUtils.requireParameter(trustAnchorArn, "Trust anchor ARN");
        this.trustAnchorArn = trustAnchorArn;
        return this;
    }

    /**
     * Sets the profile ARN.
     *
     * @param profileArn The ARN string of the profile
     * @return This builder instance
     * @throws IllegalArgumentException if the ARN format is invalid or empty
     */
    CreateSessionRequestBuilder profileArn(String profileArn) {
        ValidationUtils.requireNonNullAndNonEmpty(profileArn, "Profile ARN");
        this.profileArn = ArnValidator.validateProfileArn(profileArn);
        return this;
    }

    /**
     * Sets the profile ARN.
     *
     * @param profileArn The Arn object of the profile
     * @return This builder instance
     * @throws IllegalArgumentException if the ARN is null
     */
    CreateSessionRequestBuilder profileArn(Arn profileArn) {
        ValidationUtils.requireParameter(profileArn, "Profile ARN");
        this.profileArn = profileArn;
        return this;
    }

    /**
     * Sets the role ARN.
     *
     * @param roleArn The ARN string of the role to assume
     * @return This builder instance
     * @throws IllegalArgumentException if the ARN format is invalid or empty
     */
    CreateSessionRequestBuilder roleArn(String roleArn) {
        ValidationUtils.requireNonNullAndNonEmpty(roleArn, "Role ARN");
        this.roleArn = ArnValidator.validateRoleArn(roleArn);
        return this;
    }

    /**
     * Sets the role ARN.
     *
     * @param roleArn The Arn object of the role to assume
     * @return This builder instance
     * @throws IllegalArgumentException if the ARN is null
     */
    CreateSessionRequestBuilder roleArn(Arn roleArn) {
        ValidationUtils.requireParameter(roleArn, "Role ARN");
        this.roleArn = roleArn;
        return this;
    }

    /**
     * Sets the optional role session name.
     *
     * @param roleSessionName The session name for the assumed role
     * @return This builder instance
     */
    CreateSessionRequestBuilder roleSessionName(String roleSessionName) {
        this.roleSessionName = roleSessionName;
        return this;
    }

    /**
     * Sets the AWS region for endpoint resolution.
     *
     * @param region The AWS region
     * @return This builder instance
     */
    CreateSessionRequestBuilder region(Region region) {
        this.region = region;
        return this;
    }

    /**
     * Sets a custom endpoint URI for the IAM Roles Anywhere service.
     *
     * @param customEndpoint The custom endpoint URI
     * @return This builder instance
     */
    CreateSessionRequestBuilder customEndpoint(URI customEndpoint) {
        this.customEndpoint = customEndpoint;
        return this;
    }

    /**
     * Enables or disables FIPS endpoints.
     *
     * @param fipsEnabled true to use FIPS endpoints, false otherwise
     * @return This builder instance
     */
    CreateSessionRequestBuilder fipsEnabled(boolean fipsEnabled) {
        this.fipsEnabled = fipsEnabled;
        return this;
    }

    /**
     * Enables or disables dual-stack (IPv4/IPv6) endpoints.
     *
     * @param dualStackEnabled true to use dual-stack endpoints, false otherwise
     * @return This builder instance
     */
    CreateSessionRequestBuilder dualStackEnabled(boolean dualStackEnabled) {
        this.dualStackEnabled = dualStackEnabled;
        return this;
    }

    /**
     * Sets the optional session duration in seconds.
     *
     * @param durationSeconds The session duration (900-43200 seconds)
     * @return This builder instance
     * @throws IllegalArgumentException if the duration is outside the valid range
     */
    CreateSessionRequestBuilder durationSeconds(Integer durationSeconds) {
        ValidationUtils.validateSessionDuration(durationSeconds);
        this.durationSeconds = durationSeconds;
        return this;
    }

    /**
     * Builds the SdkHttpFullRequest for the CreateSession API call.
     *
     * @return A properly formatted HTTP request for the IAM Roles Anywhere CreateSession API
     * @throws IllegalArgumentException if required parameters are missing
     */
    SdkHttpFullRequest build() {
        validateRequiredParameters();

        URI resolvedEndpoint = resolveEndpoint();

        // Add the /sessions path
        URI finalEndpoint;
        try {
            finalEndpoint =
                    new URI(
                            resolvedEndpoint.getScheme(),
                            resolvedEndpoint.getAuthority(),
                            "/sessions",
                            null);
        } catch (URISyntaxException e) {
            throw new RuntimeException("Failed to construct final endpoint URI", e);
        }

        String jsonRequestBody = buildJsonRequestBody();
        RequestBody body = RequestBody.fromString(jsonRequestBody);

        return SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(finalEndpoint)
                .putHeader("Content-Type", CONTENT_TYPE_JSON)
                .putHeader("Host", finalEndpoint.getHost())
                .contentStreamProvider(body.contentStreamProvider())
                .build();
    }

    /**
     * Builds the JSON body for the CreateSession API request parameters. ARNs are included in the
     * request body to ensure compliant SigV4 signing. Uses SDK JsonWriter for proper encoding and
     * escaping.
     *
     * @return JSON string containing the request parameters
     */
    private String buildJsonRequestBody() {
        try {
            try (JsonWriter jsonWriter = JsonWriter.create()) { // autocloseable
                jsonWriter.writeStartObject();

                jsonWriter.writeFieldName("profileArn");
                jsonWriter.writeValue(profileArn.toString());

                jsonWriter.writeFieldName("roleArn");
                jsonWriter.writeValue(roleArn.toString());

                jsonWriter.writeFieldName("trustAnchorArn");
                jsonWriter.writeValue(trustAnchorArn.toString());

                // Add optional parameters
                if (!StringUtils.isBlank(roleSessionName)) {
                    jsonWriter.writeFieldName("roleSessionName");
                    jsonWriter.writeValue(roleSessionName);
                }

                if (durationSeconds != null) {
                    jsonWriter.writeFieldName("durationSeconds");
                    jsonWriter.writeValue(durationSeconds);
                }

                jsonWriter.writeEndObject();
                return new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to build JSON request body", e);
        }
    }

    /**
     * Resolves the endpoint URI for the IAM Roles Anywhere service. Uses the FIPS and dual-stack
     * settings configured in the builder. If a custom endpoint is configured, FIPS and dual-stack
     * settings are ignored. If an explicit endpoint was set via endpoint(), that takes precedence.
     *
     * @return The resolved endpoint URI
     */
    private URI resolveEndpoint() {
        RolesAnywhereEndpointParams.Builder paramsBuilder = RolesAnywhereEndpointParams.builder();

        if (customEndpoint != null) {
            paramsBuilder.endpoint(customEndpoint.toString());
        } else {
            ValidationUtils.requireParameter(region, "Region for endpoint resolution");
            paramsBuilder.region(region);
            paramsBuilder.useFips(fipsEnabled);
            paramsBuilder.useDualStack(dualStackEnabled);
        }

        try {
            Endpoint resolvedEndpoint =
                    endpointProvider.resolveEndpoint(paramsBuilder.build()).join();
            return resolvedEndpoint.url();
        } catch (Exception e) {
            throw new RuntimeException("Failed to resolve endpoint", e);
        }
    }

    /**
     * Validates that all required parameters are present.
     *
     * @throws IllegalArgumentException if any required parameter is missing
     */
    private void validateRequiredParameters() {
        ValidationUtils.requireParameter(trustAnchorArn, "Trust anchor ARN");
        ValidationUtils.requireParameter(profileArn, "Profile ARN");
        ValidationUtils.requireParameter(roleArn, "Role ARN");
    }
}
