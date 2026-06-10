package software.amazon.awssdk.services.rolesanywhere.auth;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.spi.signer.AsyncSignRequest;
import software.amazon.awssdk.http.auth.spi.signer.AsyncSignedRequest;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.awssdk.utils.Logger;
import software.amazon.awssdk.utils.http.SdkHttpUtils;

/**
 * Implementation of SigV4-A-X509 for creating RolesAnywhere Create Session
 * signatures.
 * <p>
 * SigV4-A-X509 extends SigV4-A in a few key ways:
 * <p>
 * * The credential is an X509 certificate, not an Access Key ID
 * * The certificate is attached to the request via a new header, X-Amz-X509
 * * The signing key is any key reasonably supported by PKI infrastructure,
 * including ECDSA and RSA. In SigV4-A,
 * the signing key is derived from the Secret Access Key
 * <p>
 * This implementation uses AWS SDK v2's HttpSigner interface for modern
 * authentication patterns.
 */
public final class X509Signer implements HttpSigner<X509Identity> {
    /** Signing algorithm identifier for RSA keys using SHA-256. */
    public static final String AWS4_X509_SHA256_RSA = "AWS4-X509-RSA-SHA256";

    /** Signing algorithm identifier for ECDSA keys using SHA-256. */
    public static final String AWS4_X509_SHA256_ECDSA = "AWS4-X509-ECDSA-SHA256";

    /** Signing algorithm identifier for ML-DSA keys. */
    public static final String AWS4_X509_MLDSA = "AWS4-X509-MLDSA";

    /** Header name for the X.509 certificate. */
    public static final String X_AMZ_X509 = "X-Amz-X509";

    /** Header name for the X.509 certificate chain. */
    public static final String X_AMZ_X509_CHAIN = "X-Amz-X509-Chain";

    /** Header name for the signing timestamp. */
    public static final String X_AMZ_DATE = "X-Amz-Date";

    /** Header name for the content SHA-256 hash. */
    public static final String X_AMZ_CONTENT_SHA256 = "X-Amz-Content-Sha256";

    /** Header name for the authorization signature. */
    public static final String AUTHORIZATION = "Authorization";

    /** Header name for the user agent. */
    public static final String USER_AGENT = "User-Agent";

    /** JCA algorithm name for RSA with SHA-256. */
    public static final String JCA_SHA256_RSA = "SHA256WithRSA";

    /** JCA algorithm name for ECDSA with SHA-256. */
    public static final String JCA_SHA256_ECDSA = "SHA256WithECDSA";

    /** JCA algorithm name for ML-DSA. */
    public static final String JCA_MLDSA = "ML-DSA";

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_STAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd", Locale.ROOT).withZone(ZoneOffset.UTC);

    /** User-Agent string, initialized at class load time. */
    private static final String USER_AGENT_VALUE;

    static {
        // Generate User Agent
        String version = X509Signer.class.getPackage().getImplementationVersion();
        if (version == null) {
            version = "unknown";
        }

        String javaVersion = "java" + System.getProperty("java.version").split("\\.")[0];
        String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT).replace(" ", "");
        String osVersion = System.getProperty("os.version");
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);

        USER_AGENT_VALUE =
                String.format("CredProvider/%s (%s; %s/%s; %s)", version, javaVersion, osName, osVersion, arch);
    }

    private final String serviceName;
    private final Region region;

    private static final Logger LOG = Logger.loggerFor(X509Signer.class);

    private static final AtomicInteger THREAD_COUNTER = new AtomicInteger(0);

    private static final ThreadFactory DAEMON_THREAD_FACTORY = r -> {
        Thread t = new Thread(r, "x509-signer-" + THREAD_COUNTER.getAndIncrement());
        t.setDaemon(true);
        return t;
    };

    /** Shared executor for async signing — static so no Closeable needed */
    private static final ExecutorService DEFAULT_EXECUTOR = new ThreadPoolExecutor(
            0,
            Runtime.getRuntime().availableProcessors() * 2,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            DAEMON_THREAD_FACTORY);

    private final ExecutorService executor;

    private X509Signer(Builder builder) {
        this.serviceName = builder.serviceName;
        this.region = builder.region;
        this.executor = builder.executor != null ? builder.executor : DEFAULT_EXECUTOR;
    }

    /**
     * Creates a new builder for constructing an X509Signer instance.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public SignedRequest sign(SignRequest<? extends X509Identity> signRequest) {
        X509Identity identity = signRequest.identity();
        SdkHttpRequest request = signRequest.request();

        PrivateKey privateKey = identity.privateKey();
        X509Certificate certificate = identity.certificate();
        Collection<X509Certificate> certificateChain = identity.certificateChain();

        String signingAlgorithm = determineSigningAlgorithm(privateKey);
        Instant signingTime = Instant.now();

        try {
            // Build new request with additional headers
            SdkHttpRequest.Builder requestBuilder = request.toBuilder();

            // Add timestamp
            String timestamp = DATE_FORMAT.format(signingTime);
            requestBuilder.putHeader(X_AMZ_DATE, timestamp);

            // Add User-Agent header
            requestBuilder.putHeader(USER_AGENT, USER_AGENT_VALUE);

            // Add host header if not present
            if (!request.headers().containsKey("Host")) {
                requestBuilder.putHeader("Host", request.host());
            }

            // Add X.509 certificate headers
            requestBuilder.putHeader(X_AMZ_X509, CertificateUtils.certificateToString(certificate));

            // Add certificate chain if provided
            if (certificateChain != null && !certificateChain.isEmpty()) {
                String chainHeader = certificateChain.stream()
                        .map(cert -> {
                            try {
                                return CertificateUtils.certificateToString(cert);
                            } catch (CertificateEncodingException exc) {
                                throw new IllegalArgumentException("Cannot encode certificate", exc);
                            }
                        })
                        .collect(Collectors.joining(","));
                requestBuilder.putHeader(X_AMZ_X509_CHAIN, chainHeader);
            }

            // Calculate content hash
            String contentHash = calculateContentHash(signRequest);

            // Add X-Amz-Content-Sha256 header if it's already present in the request
            // or if it's marked as "required"
            if (request.headers().containsKey(X_AMZ_CONTENT_SHA256)
                    || "required"
                            .equals(request.firstMatchingHeader(X_AMZ_CONTENT_SHA256)
                                    .orElse(null))) {
                requestBuilder.putHeader(X_AMZ_CONTENT_SHA256, contentHash);
            }

            SdkHttpRequest modifiedRequest = requestBuilder.build();

            // Create a new SignRequest with the modified request for helper methods
            SignRequest.Builder<? extends X509Identity> modifiedSignRequestBuilder =
                    SignRequest.builder(identity).request(modifiedRequest);
            if (signRequest.payload().isPresent()) {
                modifiedSignRequestBuilder.payload(signRequest.payload().get());
            }
            SignRequest<? extends X509Identity> modifiedSignRequest = modifiedSignRequestBuilder.build();

            // Create canonical request
            String canonicalRequest = createCanonicalRequest(modifiedSignRequest, contentHash);

            // Create string to sign
            String stringToSign = createStringToSign(canonicalRequest, signingTime, signingAlgorithm);

            // Compute signature
            byte[] signature = computeX509Signature(stringToSign, privateKey, signingAlgorithm);

            // Build authorization header
            String authHeader = buildAuthorizationHeader(
                    modifiedSignRequest, signature, certificate, signingTime, signingAlgorithm);

            SdkHttpRequest finalRequest = modifiedRequest.toBuilder()
                    .putHeader(AUTHORIZATION, authHeader)
                    .build();

            return SignedRequest.builder().request(finalRequest).build();

        } catch (CertificateEncodingException exc) {
            throw new SecurityException("Could not serialize certificate for request signing", exc);
        }
    }

    @Override
    public CompletableFuture<AsyncSignedRequest> signAsync(AsyncSignRequest<? extends X509Identity> asyncSignRequest) {
        return CompletableFuture.supplyAsync(
                () -> {
                    SignRequest.Builder<? extends X509Identity> signRequest =
                            SignRequest.builder(asyncSignRequest.identity()).request(asyncSignRequest.request());
                    byte[] collectedBytes = null;
                    if (asyncSignRequest.payload().isPresent()) {
                        collectedBytes = PublisherBytes.collect(
                                asyncSignRequest.payload().get());
                        final byte[] payloadForSign = collectedBytes;
                        signRequest.payload(() -> new ByteArrayInputStream(payloadForSign));
                    }
                    SignedRequest syncResult = sign(signRequest.build());
                    AsyncSignedRequest.Builder asyncResultBuilder =
                            AsyncSignedRequest.builder().request(syncResult.request());
                    if (collectedBytes != null) {
                        final byte[] payloadBytes = collectedBytes;
                        asyncResultBuilder.payload(PublisherBytes.toPublisher(payloadBytes));
                    }
                    return asyncResultBuilder.build();
                },
                executor);
    }

    /**
     * Sign a request with {@link SdkHttpFullRequest} and {@link X509Identity}.
     *
     * @param request  SdkHttpFullRequest to convert to sign request
     * @param identity used to convert to sign request
     * @return resulting signature from this signer
     */
    public SignedRequest sign(SdkHttpFullRequest request, X509Identity identity) {
        SignRequest.Builder<? extends X509Identity> srb =
                SignRequest.builder(identity).request(request);
        if (request.contentStreamProvider().isPresent()) {
            srb.payload(request.contentStreamProvider().get());
        }
        SignRequest<? extends X509Identity> sr = srb.build();
        return sign(sr);
    }

    /**
     * Sign a request with private key and certificate.
     *
     * @param request     the HTTP request to sign
     * @param privateKey  the private key used for signing
     * @param certificate the X.509 certificate containing the public key
     * @return the signed request with authentication headers added
     */
    public SignedRequest sign(SdkHttpFullRequest request, PrivateKey privateKey, X509Certificate certificate) {
        return sign(request, privateKey, certificate, null);
    }

    /**
     * Given a SdkHttpFullRequest, private key, certificate, and intermediate
     * certificates, calculate a signature derived from a canonicalized request.
     * This method will also modify the request by adding headers containing
     * values calculated during the signing operation, including the
     * Authorization header. As with SigV4 and SigV4-A, the Authorization header
     * contains both the signature, and the request's relevant metadata
     * (which headers were signed, region target, date, service).
     *
     * @param request          Request to sign
     * @param privateKey       Private key used to sign
     * @param certificate      Certificate establishing the identity of the signer,
     *                         and containing the public key to verify the signature
     * @param certificateChain Intermediate certificates that will be used to build
     *                         a trust chain
     * @return the signed request with authentication headers added
     * @throws SecurityException Thrown if the certificate could not be correctly
     *                           processed
     */
    public SignedRequest sign(
            SdkHttpFullRequest request,
            PrivateKey privateKey,
            X509Certificate certificate,
            Collection<X509Certificate> certificateChain)
            throws SecurityException {

        // Create X509Identity and SignRequest to delegate to the new sign method
        X509Identity identity = new X509Identity(certificate, privateKey, certificateChain);

        SignRequest.Builder<X509Identity> signRequestBuilder =
                SignRequest.builder(identity).request(request);

        // Extract payload from SdkHttpFullRequest if present
        // populate it in SignRequest
        if (request.contentStreamProvider().isPresent()) {
            try {
                // Pass the content stream provider directly to SignRequest
                signRequestBuilder.payload(request.contentStreamProvider().get());
            } catch (Exception e) {
                throw new RuntimeException("Failed to extract payload from SdkHttpFullRequest", e);
            }
        }

        return sign(signRequestBuilder.build());
    }

    private String determineSigningAlgorithm(PrivateKey privateKey) {
        if (privateKey instanceof ECPrivateKey) {
            return AWS4_X509_SHA256_ECDSA;
        } else if (privateKey instanceof RSAPrivateKey) {
            return AWS4_X509_SHA256_RSA;
        } else if (privateKey.getAlgorithm().contains("ML-DSA")) {
            return AWS4_X509_MLDSA;
        } else {
            throw new IllegalArgumentException("Unsupported private key type: " + privateKey.getClass());
        }
    }

    private String calculateContentHash(SignRequest<? extends X509Identity> signRequest) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Use query parameters as payload if content missing and is POST request
            if (useQueryParametersForPayload(signRequest)) {
                // Generate the same way that v1 does: without using our existing canonical
                // query string function
                final Map<String, List<String>> requestParams =
                        signRequest.request().rawQueryParameters();

                if (requestParams.isEmpty()) {
                    return BinaryUtils.toHex(digest.digest(new byte[0]));
                }

                final List<NameValuePair> nameValuePairs = new ArrayList<>();

                for (Map.Entry<String, List<String>> entry : requestParams.entrySet()) {
                    String parameterName = entry.getKey();
                    for (String value : entry.getValue()) {
                        nameValuePairs.add(new BasicNameValuePair(parameterName, value));
                    }
                }
                final String encodedParameters = URLEncodedUtils.format(nameValuePairs, StandardCharsets.UTF_8);
                return BinaryUtils.toHex(digest.digest((encodedParameters.getBytes(StandardCharsets.UTF_8))));
            }

            // Use payload directly from SignRequest if available
            if (signRequest.payload().isPresent()) {
                try (java.io.InputStream inputStream =
                        signRequest.payload().get().newStream()) {
                    byte[] content = inputStream.readAllBytes();
                    return BinaryUtils.toHex(digest.digest(content));
                } catch (Exception e) {
                    // Don't want to throw when possible to succeed if payload is ""
                    LOG.error(() -> "Exception while parsing request payload contents", e);
                }
            }

            return BinaryUtils.toHex(digest.digest(new byte[0]));
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate content hash", e);
        }
    }

    private String createCanonicalRequest(SignRequest<? extends X509Identity> signRequest, String contentHash) {
        final StringBuilder canonical = new StringBuilder();

        // HTTP method
        canonical.append(signRequest.request().method().name()).append('\n');

        // Canonical URI
        String path = signRequest.request().encodedPath();
        if (path.isEmpty()) {
            path = "/";
        }
        canonical.append(path).append('\n');

        // Canonical query string
        String canonicalQueryString = ""; // Included if hash is of payload
        if (!useQueryParametersForPayload(signRequest)) {
            canonicalQueryString = getCanonicalQueryString(signRequest);
        }

        canonical.append(canonicalQueryString).append('\n');

        // Canonical headers
        canonical.append(getCanonicalHeaders(signRequest)).append('\n');

        // Signed headers
        canonical.append(getSignedHeaders(signRequest)).append('\n');

        // Content hash
        canonical.append(contentHash);

        return canonical.toString();
    }

    /**
     * Re-implementation of AWS Signature v4 method used for generating hash/query
     * params.
     *
     * @param signRequest The sign request we need to evaluate
     * @return whether to use query parameters as payload
     */
    private boolean useQueryParametersForPayload(SignRequest<? extends X509Identity> signRequest) {
        SdkHttpRequest request = signRequest.request();
        boolean isPost = SdkHttpMethod.POST.equals(request.method());
        boolean isEmpty = signRequest.payload().isEmpty();
        return isPost && isEmpty;
    }

    /**
     * Roughly equivalent to SDK v1's SdkHttpUtils.encodeParameters(request)
     *
     * @param signRequest The sign request we will evaluate
     * @return request's query strings sorted by key, sdk v2 url encoded skipping =
     *         and &
     */
    private String getCanonicalQueryString(SignRequest<? extends X509Identity> signRequest) {
        SdkHttpRequest request = signRequest.request();
        return request.rawQueryParameters().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .flatMap(entry -> entry.getValue().stream()
                        .map(value -> SdkHttpUtils.urlEncode(entry.getKey()) + "=" + SdkHttpUtils.urlEncode(value)))
                .collect(Collectors.joining("&"));
    }

    private String getCanonicalHeaders(SignRequest<? extends X509Identity> signRequest) {
        SdkHttpRequest request = signRequest.request();
        return request.headers().entrySet().stream()
                .filter(entry -> shouldSignHeader(entry.getKey()))
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .map(entry -> entry.getKey().toLowerCase(Locale.ROOT) + ":"
                        + String.join(",", entry.getValue()).trim() + "\n")
                .collect(Collectors.joining());
    }

    private String getSignedHeaders(SignRequest<? extends X509Identity> signRequest) {
        SdkHttpRequest request = signRequest.request();
        return request.headers().keySet().stream()
                .filter(this::shouldSignHeader)
                .map(header -> header.toLowerCase(Locale.ROOT))
                .sorted()
                .collect(Collectors.joining(";"));
    }

    private boolean shouldSignHeader(String headerName) {
        String lowerName = headerName.toLowerCase(Locale.ROOT);
        return lowerName.startsWith("x-amz-")
                || lowerName.equals("host")
                || lowerName.equals("content-type")
                || lowerName.equals("content-length")
                || lowerName.equals("authorization");
    }

    private String createStringToSign(String canonicalRequest, Instant signingTime, String algorithm) {
        String dateStamp = DATE_STAMP_FORMAT.format(signingTime);
        String timestamp = DATE_FORMAT.format(signingTime);
        String scope = dateStamp + "/" + region.id() + "/" + serviceName + "/aws4_request";

        // Hash canonical request using same approach as AbstractAWSSigner
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(canonicalRequest.getBytes(StandardCharsets.UTF_8));
            String hashedCanonicalRequest = BinaryUtils.toHex(md.digest());

            return algorithm + "\n" + timestamp + "\n" + scope + "\n" + hashedCanonicalRequest;
        } catch (Exception e) {
            throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }

    private byte[] computeX509Signature(String stringToSign, PrivateKey signingKey, String algorithm) {
        String jcaAlgorithm;
        if (AWS4_X509_SHA256_RSA.equals(algorithm)) {
            jcaAlgorithm = JCA_SHA256_RSA;
        } else if (AWS4_X509_SHA256_ECDSA.equals(algorithm)) {
            jcaAlgorithm = JCA_SHA256_ECDSA;
        } else if (AWS4_X509_MLDSA.equals(algorithm)) {
            jcaAlgorithm = JCA_MLDSA;
        } else {
            throw new IllegalArgumentException("Unsupported signing algorithm: " + algorithm
                    + ". Only " + AWS4_X509_SHA256_RSA + ", " + AWS4_X509_SHA256_ECDSA + " or "
                    + AWS4_X509_MLDSA + " are supported.");
        }

        try {
            Signature signer = Signature.getInstance(jcaAlgorithm);
            signer.initSign(signingKey);
            signer.update(stringToSign.getBytes(StandardCharsets.US_ASCII));
            return signer.sign();
        } catch (NoSuchAlgorithmException exc) {
            throw new RuntimeException(
                    "No JCE provider found for algorithm '" + jcaAlgorithm + "'. "
                            + "Ensure a provider supporting this algorithm is registered via "
                            + "Security.addProvider() before signing.",
                    exc);
        } catch (InvalidKeyException | SignatureException exc) {
            throw new RuntimeException("Failed to compute X.509 signature", exc);
        }
    }

    private String buildAuthorizationHeader(
            SignRequest<? extends X509Identity> signRequest,
            byte[] signature,
            X509Certificate certificate,
            Instant signingTime,
            String algorithm) {
        String dateStamp = DATE_STAMP_FORMAT.format(signingTime);
        final String scope = dateStamp + "/" + region.id() + "/" + serviceName + "/aws4_request";
        final String credential = certificate.getSerialNumber().toString() + "/" + scope;
        String signedHeaders = getSignedHeaders(signRequest);

        return algorithm + " "
                + "Credential=" + credential + ", "
                + "SignedHeaders=" + signedHeaders + ", "
                + "Signature=" + BinaryUtils.toHex(signature);
    }

    /**
     * Builder class for constructing X509Signer instances.
     */
    public static class Builder {
        private String serviceName;
        private Region region;
        private ExecutorService executor;

        /**
         * Sets the AWS service name for signing.
         *
         * @param serviceName the AWS service name (e.g., "rolesanywhere")
         * @return this builder instance for method chaining
         */
        public Builder serviceName(String serviceName) {
            this.serviceName = serviceName;
            return this;
        }

        /**
         * Sets the AWS region for signing.
         *
         * @param region the AWS region where the service is located
         * @return this builder instance for method chaining
         */
        public Builder region(Region region) {
            this.region = region;
            return this;
        }

        /**
         * Override the default executor used by signAsync.
         *
         * @param executor the executor service to use
         * @return this builder instance for method chaining
         */
        public Builder executor(ExecutorService executor) {
            this.executor = executor;
            return this;
        }

        /**
         * Builds the X509Signer instance with the configured parameters.
         *
         * @return a new X509Signer instance
         * @throws IllegalArgumentException if required parameters are missing
         */
        public X509Signer build() {
            ValidationUtils.requireParameter(serviceName, "serviceName");
            ValidationUtils.requireParameter(region, "region");
            return new X509Signer(this);
        }
    }
}
