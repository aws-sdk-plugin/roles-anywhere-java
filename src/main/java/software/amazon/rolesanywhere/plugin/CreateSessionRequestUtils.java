package software.amazon.rolesanywhere.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkServiceException;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;

/**
 * Utility class for executing HTTP requests and handling responses for IAM
 * Roles Anywhere operations.
 */
final class CreateSessionRequestUtils {

    static final String UNPARSEABLE_RESPONSE_MESSAGE = "Service returned an error response that could not be parsed";
    static final String MISSING_MESSAGE_FIELD = "Service returned an error response with no message field";

    private CreateSessionRequestUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Executes a signed HTTP request and returns the response body as a string.
     *
     * @param signedRequest The signed HTTP request to execute
     * @param httpClient    The HTTP client to use for execution
     * @return The response body as a string
     * @throws SdkClientException  if there's a network connectivity issue
     * @throws SdkServiceException if the service returns an error response
     */
    static String executeHttpRequest(
            SdkHttpFullRequest request, SignedRequest signedRequest, SdkHttpClient httpClient) {
        try {
            // Execute request using SDK client
            HttpExecuteRequest.Builder executeRequestBuilder =
                    HttpExecuteRequest.builder().request(signedRequest.request()); // signed sdkrequest is used

            // unfortunately the signRequest.payload is not equivalent here and causes
            // Invalid signature
            // So we make sure to use the provider from the full request used to create
            // signed request
            if (request.contentStreamProvider().isPresent()) {
                executeRequestBuilder.contentStreamProvider(
                        request.contentStreamProvider().get());
            }

            HttpExecuteResponse executeResponse =
                    httpClient.prepareRequest(executeRequestBuilder.build()).call();
            SdkHttpResponse response = executeResponse.httpResponse();

            // Validate HTTP status code
            int statusCode = response.statusCode();
            String responseBody = readResponseBody(executeResponse);

            // On success return response body
            if (statusCode >= 200 && statusCode < 300) {
                return responseBody;
            } else {
                throwSDKErrorEquivalent(statusCode, responseBody);
                throw new AssertionError("unreachable");
            }

        } catch (IOException e) {
            throw SdkClientException.builder()
                    .message("Failed to execute HTTP request to IAM Roles Anywhere service")
                    .cause(e)
                    .build();
        } catch (Exception e) {
            // preserve intentionally thrown exceptions
            if (e instanceof SdkClientException || e instanceof SdkServiceException) {
                throw e;
            }
            // safely handle unexpected exceptions
            throw SdkClientException.builder()
                    .message("Unexpected error during HTTP request execution")
                    .cause(e)
                    .build();
        }
    }

    /**
     * Reads the response body from an HTTP response and converts it to a string.
     *
     * @param response The HTTP response
     * @return The response body as a string
     * @throws IOException if there's an error reading the response
     */
    private static String readResponseBody(HttpExecuteResponse response) throws IOException {
        if (response.responseBody().isPresent()) {
            try (InputStream inputStream = response.responseBody().get()) {
                return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    /**
     * Handles HTTP error responses by throwing equivalent SDK exceptions.
     *
     * @param statusCode   The HTTP status code
     * @param responseBody The response body containing error details
     * @throws SdkServiceException with appropriate error details
     */
    private static void throwSDKErrorEquivalent(int statusCode, String responseBody) {
        String errorMessage = extractErrorMessage(responseBody);

        SdkServiceException.Builder exceptionBuilder =
                SdkServiceException.builder().statusCode(statusCode);

        // Map of status codes to their default error messages
        Map<Integer, String> statusCodeMessages = Map.of(
                400, "Bad Request: Invalid request parameters",
                401, "Unauthorized: Authentication failed",
                403, "Forbidden: Access denied",
                404, "Not Found: Resource not found",
                429, "Too Many Requests: Rate limit exceeded");

        String finalMessage;
        if (statusCodeMessages.containsKey(statusCode)) {
            String msg = statusCodeMessages.get(statusCode);
            String prefix = msg.substring(0, msg.indexOf(':') + 1);
            if (errorMessage.isEmpty()) {
                finalMessage = statusCodeMessages.get(statusCode);
            } else {
                finalMessage = prefix + " " + errorMessage;
            }
        } else if (statusCode >= 500) {
            if (errorMessage.isEmpty()) {
                finalMessage = "Server Error: Internal server error";
            } else {
                finalMessage = "Server Error: " + errorMessage;
            }
        } else {
            finalMessage = errorMessage.isEmpty() ? "IAM Roles Anywhere service error" : errorMessage;
        }

        exceptionBuilder.message(finalMessage);
        throw exceptionBuilder.build();
    }

    /**
     * Extracts error message from response body using JsonNode.
     *
     * @param responseBody The response body
     * @return Extracted error message or empty string if none found
     */
    static String extractErrorMessage(String responseBody) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return "";
        }

        try {
            JsonNode jsonNode = JsonNode.parser().parse(responseBody);
            JsonNode messageNode = jsonNode.field("Message")
                    .or(() -> jsonNode.field("message"))
                    .orElse(null);

            if (messageNode != null && messageNode.isString()) {
                return messageNode.asString();
            }
            return MISSING_MESSAGE_FIELD;
        } catch (Exception e) {
            // If JSON parsing fails, return safe message to avoid leaking raw response content
            return UNPARSEABLE_RESPONSE_MESSAGE;
        }
    }

    /**
     * Parses the CreateSession response JSON to extract AWS credentials using
     * regex-based parsing.
     *
     * @param responseBody The JSON response body from the CreateSession API
     * @return AwsSessionCredentials extracted from the response
     * @throws SdkClientException if the response cannot be parsed or is missing
     *                            required fields
     */
    static AwsSessionCredentials parseCreateSessionResponse(String responseBody) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            throw SdkClientException.builder()
                    .message("Empty response body from IAM Roles Anywhere service")
                    .build();
        }

        try {
            JsonNode jsonNode = JsonNode.parser().parse(responseBody);

            // Navigate to credentialSet[0].credentials
            JsonNode credentialSetNode = jsonNode.field("credentialSet").orElse(null);
            if (credentialSetNode == null
                    || !credentialSetNode.isArray()
                    || credentialSetNode.asArray().isEmpty()) {
                throw SdkClientException.builder()
                        .message("Invalid response from IAM Roles Anywhere service: missing credentialSet")
                        .build();
            }

            JsonNode firstCredentialSet = credentialSetNode.asArray().get(0);
            JsonNode credentialsNode = firstCredentialSet.field("credentials").orElse(null);

            if (credentialsNode == null) {
                throw SdkClientException.builder()
                        .message("Invalid response from IAM Roles Anywhere service: missing credentials")
                        .build();
            }

            // Extract credential fields
            String accessKeyId;
            String secretAccessKey;
            String sessionToken;
            Instant expiration;
            try {
                accessKeyId = unwrapStringJsonSubNode(credentialsNode, "accessKeyId");
                secretAccessKey = unwrapStringJsonSubNode(credentialsNode, "secretAccessKey");
                sessionToken = unwrapStringJsonSubNode(credentialsNode, "sessionToken");
                expiration = Instant.parse(unwrapStringJsonSubNode(credentialsNode, "expiration"));
            } catch (SdkClientException e) {
                throw SdkClientException.builder()
                        .message("Invalid response from IAM Roles Anywhere service: missing required credential fields")
                        .cause(e)
                        .build();
            }

            return AwsSessionCredentials.builder()
                    .accessKeyId(accessKeyId)
                    .sessionToken(sessionToken)
                    .secretAccessKey(secretAccessKey)
                    .expirationTime(expiration)
                    .build();

        } catch (Exception e) {
            if (e instanceof SdkClientException) {
                throw e;
            }
            throw SdkClientException.builder()
                    .message("Failed to parse CreateSession response: " + e.getMessage())
                    .cause(e)
                    .build();
        }
    }

    private static String unwrapStringJsonSubNode(JsonNode parentNode, String subNodeName) throws SdkClientException {
        JsonNode subNode = parentNode.field(subNodeName).orElse(null);
        if (subNode == null || !subNode.isString()) {
            throw SdkClientException.builder()
                    .message("Failed to get " + subNodeName + " from credentials response")
                    .build();
        }
        return subNode.asString();
    }
}
