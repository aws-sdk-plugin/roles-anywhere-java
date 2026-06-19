package software.amazon.rolesanywhere.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkServiceException;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;

class CreateSessionRequestUtilsTest {

    @Mock
    private SdkHttpClient httpClient;

    @Mock
    private SignedRequest signedRequest;

    @Mock
    private SdkHttpRequest httpRequest;

    @Mock
    private SdkHttpFullRequest httpFullRequest;

    @Mock
    private ExecutableHttpRequest executableRequest;

    @Mock
    private HttpExecuteResponse httpResponse;

    @Mock
    private SdkHttpResponse sdkHttpResponse;

    CreateSessionRequestUtilsTest() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void executeHttpRequestSuccessfulResponseReturnsResponseBody() throws Exception {
        // Arrange
        String expectedResponse = "{\"message\":\"success\"}";
        AbortableInputStream responseStream = AbortableInputStream.create(
                new ByteArrayInputStream(expectedResponse.getBytes(StandardCharsets.UTF_8)));

        when(signedRequest.request()).thenReturn(httpRequest);
        when(httpClient.prepareRequest(any(HttpExecuteRequest.class))).thenReturn(executableRequest);
        when(executableRequest.call()).thenReturn(httpResponse);
        when(httpResponse.httpResponse()).thenReturn(sdkHttpResponse);
        when(sdkHttpResponse.statusCode()).thenReturn(200); // success code
        when(httpResponse.responseBody()).thenReturn(Optional.of(responseStream));

        // Act
        String result = CreateSessionRequestUtils.executeHttpRequest(httpFullRequest, signedRequest, httpClient);

        // Assert
        assertEquals(expectedResponse, result);
    }

    @Test
    void executeHttpRequest201CreatedResponseReturnsResponseBody() throws Exception {
        // Arrange
        String expectedResponse = "{\"credentialSet\":[{\"credentials\":"
                + "{\"accessKeyId\":\"AKIATEST\",\"secretAccessKey\":\"secret\","
                + "\"sessionToken\":\"token\"}}]}";
        AbortableInputStream responseStream = AbortableInputStream.create(
                new ByteArrayInputStream(expectedResponse.getBytes(StandardCharsets.UTF_8)));

        when(signedRequest.request()).thenReturn(httpRequest);
        when(httpClient.prepareRequest(any(HttpExecuteRequest.class))).thenReturn(executableRequest);
        when(executableRequest.call()).thenReturn(httpResponse);
        when(httpResponse.httpResponse()).thenReturn(sdkHttpResponse);
        when(sdkHttpResponse.statusCode()).thenReturn(201); // created code
        when(httpResponse.responseBody()).thenReturn(Optional.of(responseStream));

        // Act
        String result = CreateSessionRequestUtils.executeHttpRequest(httpFullRequest, signedRequest, httpClient);

        // Assert
        assertEquals(expectedResponse, result);
    }

    @Test
    void executeHttpRequestErrorResponseThrowsSdkServiceException() throws Exception {
        // Arrange
        String errorResponse = "{\"message\":\"Invalid request\"}";
        AbortableInputStream responseStream =
                AbortableInputStream.create(new ByteArrayInputStream(errorResponse.getBytes(StandardCharsets.UTF_8)));

        when(signedRequest.request()).thenReturn(httpRequest);
        when(httpClient.prepareRequest(any(HttpExecuteRequest.class))).thenReturn(executableRequest);
        when(executableRequest.call()).thenReturn(httpResponse);
        when(httpResponse.httpResponse()).thenReturn(sdkHttpResponse);
        when(sdkHttpResponse.statusCode()).thenReturn(400); // invalid request code
        when(httpResponse.responseBody()).thenReturn(Optional.of(responseStream));

        // Act & Assert
        SdkServiceException exception = assertThrows(
                SdkServiceException.class,
                () -> CreateSessionRequestUtils.executeHttpRequest(httpFullRequest, signedRequest, httpClient));

        assertTrue(exception.getMessage().contains("Bad Request"));
    }

    @Test
    void executeHttpRequestIoExceptionThrowsSdkClientException() throws Exception {
        // Arrange
        when(signedRequest.request()).thenReturn(httpRequest);
        when(httpClient.prepareRequest(any(HttpExecuteRequest.class))).thenReturn(executableRequest);
        when(executableRequest.call()).thenThrow(new IOException("Network error"));

        // Act & Assert
        SdkClientException exception = assertThrows(
                SdkClientException.class,
                () -> CreateSessionRequestUtils.executeHttpRequest(httpFullRequest, signedRequest, httpClient));

        assertTrue(exception.getMessage().contains("Failed to execute HTTP request"));
        assertInstanceOf(IOException.class, exception.getCause());
    }

    @Test
    void extractErrorMessageWithCapitalMessage() {
        String json = "{\"Message\":\"Custom error\"}";
        assertEquals("Custom error", CreateSessionRequestUtils.extractErrorMessage(json));
    }

    @Test
    void extractErrorMessageWithLowercaseMessage() {
        String json = "{\"message\":\"Another error\"}";
        assertEquals("Another error", CreateSessionRequestUtils.extractErrorMessage(json));
    }

    @Test
    void extractErrorMessageWithInvalidJson() {
        String invalid = "not valid json";
        assertEquals(
                CreateSessionRequestUtils.UNPARSEABLE_RESPONSE_MESSAGE,
                CreateSessionRequestUtils.extractErrorMessage(invalid));
    }

    @Test
    void extractErrorMessageWithValidJsonButNoMessageField() {
        String json = "{\"Error\": {\"Code\": \"AccessDenied\"}}";
        assertEquals(
                CreateSessionRequestUtils.MISSING_MESSAGE_FIELD, CreateSessionRequestUtils.extractErrorMessage(json));
    }
}
