package software.amazon.awssdk.services.rolesanywhere.auth;

import java.util.Map;

import software.amazon.awssdk.arns.Arn;

/**
 * Utility class for validating ARNs used in IAM Roles Anywhere operations.
 * This class provides validation for trust anchor, profile, and role ARNs.
 */
final class ArnValidator {

    // ARN validation constants
    private static final String ROLESANYWHERE_SERVICE = "rolesanywhere";
    private static final String IAM_SERVICE = "iam";
    private static final String TRUST_ANCHOR_RESOURCE_TYPE = "trust-anchor";
    private static final String PROFILE_RESOURCE_TYPE = "profile";
    private static final String ROLE_RESOURCE_TYPE = "role";
    private static final Map<String, String> RESOURCE_TYPES = Map.of(
            TRUST_ANCHOR_RESOURCE_TYPE,
            "arn:<partition>:rolesanywhere:<region>:<account>:trust-anchor/<trust-anchor-id>",
            ROLE_RESOURCE_TYPE, "arn:<partition>:iam::<account>:role/<role-name>",
            PROFILE_RESOURCE_TYPE, "arn:<partition>:rolesanywhere:<region>:<account>:profile/<profile-id>");

    private ArnValidator() {
        // Utility class - prevent instantiation
    }

    /**
     * Parses and validates a trust anchor ARN.
     *
     * @param arnString The ARN string to validate
     * @return The parsed and validated Arn object
     * @throws IllegalArgumentException if the ARN is invalid
     */
    static Arn validateTrustAnchorArn(String arnString) {
        return parseAndValidateArn(arnString, TRUST_ANCHOR_RESOURCE_TYPE);
    }

    /**
     * Parses and validates a profile ARN.
     *
     * @param arnString The ARN string to validate
     * @return The parsed and validated Arn object
     * @throws IllegalArgumentException if the ARN is invalid
     */
    static Arn validateProfileArn(String arnString) {
        return parseAndValidateArn(arnString, PROFILE_RESOURCE_TYPE);
    }

    /**
     * Parses and validates a role ARN.
     *
     * @param arnString The ARN string to validate
     * @return The parsed and validated Arn object
     * @throws IllegalArgumentException if the ARN is invalid
     */
    static Arn validateRoleArn(String arnString) {
        return parseAndValidateArn(arnString, ROLE_RESOURCE_TYPE);
    }

    /**
     * Parses and validates an ARN string for the specified resource type.
     *
     * @param arnString    The ARN string to validate
     * @param resourceType The expected resource type
     * @return The parsed and validated Arn object
     * @throws IllegalArgumentException if the ARN is invalid
     */
    private static Arn parseAndValidateArn(String arnString, String resourceType) {
        if (!RESOURCE_TYPES.containsKey(resourceType)) {
            throw new IllegalArgumentException("Resource Type provided to parseAndValidateArn was not one of "
                    + String.join(", ", RESOURCE_TYPES.keySet()) + ", but got: " + resourceType);
        }

        Arn arn;
        try {
            arn = Arn.fromString(arnString);
        } catch (IllegalArgumentException iae) {
            throw new IllegalArgumentException("Expected: "
                    + RESOURCE_TYPES.get(resourceType) + ", but got: " + arnString, iae);
        }

        String expectedService = ROLESANYWHERE_SERVICE;
        if (ROLE_RESOURCE_TYPE.equals(resourceType)) {
            expectedService = IAM_SERVICE;
        }

        if (!expectedService.equals(arn.service())) {
            throw new IllegalArgumentException(
                    "Invalid " + resourceType + " ARN service, got: " + arn.service());
        }

        if (arn.resource().resourceType().isEmpty() || !resourceType.equals(arn.resource().resourceType().get())) {
            throw new IllegalArgumentException(
                    "Invalid " + resourceType + " ARN resource type. Expected: " + resourceType);
        }

        return arn;
    }
}
