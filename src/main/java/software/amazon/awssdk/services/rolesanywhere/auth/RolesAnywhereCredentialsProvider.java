package software.amazon.awssdk.services.rolesanywhere.auth;

import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.Logger;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;

/**
 * AWS Credentials Provider for IAM Roles Anywhere.
 * This provider obtains temporary credentials using IAM Roles Anywhere service.
 * Usage:
 *
 * <pre>{@code
 * // Create the provider — load certificate and key inside the lambda to minimize
 * // the time the private key is held in memory
 * RolesAnywhereCredentialsProvider rolesAnywhereCredProvider = RolesAnywhereCredentialsProvider.builder()
 *         .profileArn(PROFILE_ARN)
 *         .roleArn(ROLE_ARN)
 *         .trustAnchorArn(TRUST_ANCHOR_ARN)
 *         .identityProvider(() -> {
 *             X509Certificate cert = CertificateUtils.loadCertificate(certPath);
 *             PrivateKey key = CertificateUtils.loadPrivateKey(keyPath, "RSA");
 *             return new X509Identity(cert, key);
 *         })
 *         .region(Region.US_EAST_1)
 *         .build();
 * // Create an AWS Client
 * RolesAnywhereClient client = RolesAnywhereClient.builder()
 *         .credentialsProvider(rolesAnywhereCredProvider)
 *         .build();
 * // Use credentials with your client
 * ListTrustAnchorsRequest listTrustAnchorRequest = ListTrustAnchorsRequest.builder()
 *         .build();
 * client.listTrustAnchors(listTrustAnchorRequest);
 * }</pre>
 */
public final class RolesAnywhereCredentialsProvider implements AwsCredentialsProvider {
    private static final Logger LOG = Logger.loggerFor(RolesAnywhereCredentialsProvider.class);

    // HTTP client configuration
    private static final Duration DEFAULT_CONNECTION_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_SOCKET_TIMEOUT = Duration.ofSeconds(30);

    // Credential refresh configuration
    private static final Duration DEFAULT_MIN_REFRESH_INTERVAL = Duration.ofMinutes(5);
    private static final Duration MIN_REFRESH_INTERVAL_FLOOR = Duration.ofSeconds(30);

    // IAM Roles Anywhere session configuration
    private final X509IdentityProvider identityProvider;
    private final Arn trustAnchorArn;
    private final Arn profileArn;
    private final Arn roleArn;
    private final Region region;
    private final String roleSessionName;
    private final Integer durationSeconds;

    // Endpoint configuration
    private final URI customEndpoint;
    private final boolean fipsEnabled;
    private final boolean dualStackEnabled;
    private final SdkHttpClient httpClient;

    // Credential cache and refresh settings
    private AwsCredentials cachedCredentials;
    private final Duration staleTime;
    private final Duration minRefreshInterval;
    private Instant lastRefreshTime = Instant.EPOCH;

    private RolesAnywhereCredentialsProvider(Builder builder) {
        this.identityProvider = builder.identityProvider;
        this.trustAnchorArn = builder.trustAnchorArn;
        this.profileArn = builder.profileArn;
        this.roleArn = builder.roleArn;
        this.region = builder.region;
        this.roleSessionName = builder.roleSessionName;
        this.durationSeconds = builder.durationSeconds;
        this.customEndpoint = builder.customEndpoint;
        this.fipsEnabled = builder.fipsEnabled;
        this.dualStackEnabled = builder.dualStackEnabled;
        if (builder.httpClient != null) {
            this.httpClient = builder.httpClient;
        } else {
            this.httpClient = createDefaultHttpClient();
        }
        this.staleTime = builder.staleTime;
        this.minRefreshInterval = builder.minRefreshInterval;
    }

    /**
     * Creates a new builder for RolesAnywhereCredentialsProvider.
     *
     * @return A new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    private X509Identity getIdentity() throws IdentityProviderException {
        X509Identity resolved = identityProvider.create();
        if (resolved == null) {
            throw new IdentityProviderException(
                    "X509IdentityProvider returned null. "
                    + "Ensure your identityProvider returns a valid X509Identity.");
        }
        try {
            ValidationUtils.validateCertificate(resolved.certificate());
            ValidationUtils.validatePrivateKey(resolved.privateKey());
        } catch (Exception e) {
            throw new IdentityProviderException(
                    "X509IdentityProvider returned an invalid identity", e);
        }
        Instant expiryHorizon = Instant.now().plus(Duration.ofDays(30));
        warnIfExpiringSoon(resolved.certificate(), "leaf", expiryHorizon);
        int index = 0;
        for (java.security.cert.X509Certificate intermediate : resolved.certificateChain()) {
            warnIfExpiringSoon(intermediate, "chain[" + index + "]", expiryHorizon);
            index++;
        }
        return resolved;
    }

    private void warnIfExpiringSoon(java.security.cert.X509Certificate cert, String label, Instant horizon) {
        Instant notAfter = cert.getNotAfter().toInstant();
        if (horizon.isAfter(notAfter)) {
            LOG.warn(() -> "X.509 certificate (" + label
                    + ", subject=" + cert.getSubjectX500Principal().getName()
                    + ") expires within 30 days (at " + notAfter + "). "
                    + "Rotate your certificate to avoid authentication failures.");
        }
    }

    /**
     * Resolves AWS credentials for IAM Roles Anywhere.
     *
     * @return AwsCredentials containing access key, secret key, and session token
     * @throws RuntimeException wrapping an IdentityProviderException
     *         if the identity provider fails to supply an identity
     */
    @Override
    public synchronized AwsCredentials resolveCredentials() {
        // Use cache if creds and expiration time is available
        if (this.cachedCredentials != null && this.cachedCredentials.expirationTime().isPresent()) {
            // and if it is too early to refresh
            if (Instant.now().plus(staleTime).isBefore(this.cachedCredentials.expirationTime().get())) {
                return this.cachedCredentials;
            }
        }
        // Enforce minimum credential refresh interval to prevent retry storms
        if (this.cachedCredentials != null
                && Instant.now().isBefore(lastRefreshTime.plus(minRefreshInterval))) {
            return this.cachedCredentials;
        }
        // Otherwise call create session to refresh
        this.lastRefreshTime = Instant.now(); // throttle even on failure
        X509Signer signer = X509Signer.builder()
                .region(this.region)
                .serviceName("rolesanywhere").build();
        SdkHttpFullRequest request = this.createSessionRequestBuilder().build();
        SignedRequest sr;
        try {
            sr = signer.sign(request, this.getIdentity());
        } catch (IdentityProviderException e) {
            throw new RuntimeException(e);
        }
        String responseBody = CreateSessionRequestUtils.executeHttpRequest(request, sr, this.httpClient);
        this.cachedCredentials = CreateSessionRequestUtils.parseCreateSessionResponse(responseBody);
        return cachedCredentials;
    }

    /**
     * Creates a CreateSessionRequestBuilder configured with the endpoint settings
     * from this credentials provider.
     *
     * @return A configured CreateSessionRequestBuilder
     */
    CreateSessionRequestBuilder createSessionRequestBuilder() {
        CreateSessionRequestBuilder builder = new CreateSessionRequestBuilder(region)
                .trustAnchorArn(trustAnchorArn)
                .profileArn(profileArn)
                .roleArn(roleArn)
                .fipsEnabled(fipsEnabled)
                .dualStackEnabled(dualStackEnabled);

        if (roleSessionName != null) {
            builder.roleSessionName(roleSessionName);
        }
        if (durationSeconds != null) {
            builder.durationSeconds(durationSeconds);
        }
        if (customEndpoint != null) {
            builder.customEndpoint(customEndpoint);
        }

        return builder;
    }

    /**
     * Creates a default HTTP client with appropriate timeout configuration.
     *
     * @return Configured SdkHttpClient
     */
    private static SdkHttpClient createDefaultHttpClient() {
        return ApacheHttpClient.builder()
                .connectionTimeout(DEFAULT_CONNECTION_TIMEOUT)
                .socketTimeout(DEFAULT_SOCKET_TIMEOUT)
                .build();
    }

    /**
     * Builder class for RolesAnywhereCredentialsProvider with fluent API.
     */
    public static final class Builder {
        // IAM Roles Anywhere session configuration
        private X509IdentityProvider identityProvider;
        private Arn trustAnchorArn;
        private Arn profileArn;
        private Arn roleArn;
        private Region region; // Default is set during build if no override is present
        private String roleSessionName;
        private Integer durationSeconds;

        // Endpoint configuration
        private URI customEndpoint;
        private boolean fipsEnabled = false;
        private boolean dualStackEnabled = false;
        private SdkHttpClient httpClient;

        // Credential cache and refresh settings
        private Duration staleTime = Duration.ofMinutes(5);
        private Duration minRefreshInterval = DEFAULT_MIN_REFRESH_INTERVAL;

        private Builder() {
        }

        private Region resolveRegion() {
            if (region != null) {
                return region;
            }
            String regionProperty = System.getProperty("aws.region");
            if (regionProperty != null && !regionProperty.trim().isEmpty()) {
                return Region.of(regionProperty);
            }

            String regionEnv = System.getenv("AWS_REGION");
            if (regionEnv != null && !regionEnv.trim().isEmpty()) {
                return Region.of(regionEnv);
            }

            String regionFromArns = extractConsistentRegionFromArns();
            if (regionFromArns != null) {
                return Region.of(regionFromArns);
            }

            throw new IllegalArgumentException("Region could not be resolved");
        }

        /**
         * Extracts the region from ARNs if all ARNs point to the same region.
         *
         * @return The consistent region from ARNs, or null if regions are inconsistent
         *         or cannot be extracted
         */
        private String extractConsistentRegionFromArns() {
            if (trustAnchorArn == null || profileArn == null) {
                return null;
            }

            String trustAnchorRegion = trustAnchorArn.region().orElse(null);
            String profileRegion = profileArn.region().orElse(null);

            // Role ARN doesn't have a region (IAM is global), so we only check trust anchor
            // and profile
            if (trustAnchorRegion != null && trustAnchorRegion.equals(profileRegion)) {
                return trustAnchorRegion;
            }

            return null;
        }

        /**
         * Sets the X509IdentityProvider containing the certificate and private key.
         *
         * @param identityProvider The X509IdentityProvider for authentication
         * @return This builder instance
         */
        public Builder identityProvider(X509IdentityProvider identityProvider) {
            if (identityProvider == null) {
                this.identityProvider = null;
                return this;
            }
            this.identityProvider = identityProvider;
            return this;
        }

        /**
         * Sets the trust anchor ARN.
         *
         * @param trustAnchorArn The ARN string of the trust anchor
         * @return This builder instance
         * @throws IllegalArgumentException if the ARN format is invalid
         */
        public Builder trustAnchorArn(String trustAnchorArn) {
            if (ValidationUtils.nullOrEmpty(trustAnchorArn)) {
                this.trustAnchorArn = null;
                return this;
            }
            this.trustAnchorArn = ArnValidator.validateTrustAnchorArn(trustAnchorArn);
            return this;
        }

        /**
         * Sets the trust anchor ARN.
         *
         * @param trustAnchorArn The Arn object of the trust anchor
         * @return This builder instance
         */
        public Builder trustAnchorArn(Arn trustAnchorArn) {
            this.trustAnchorArn = trustAnchorArn;
            return this;
        }

        /**
         * Sets the profile ARN.
         *
         * @param profileArn The ARN string of the profile
         * @return This builder instance
         * @throws IllegalArgumentException if the ARN format is invalid
         */
        public Builder profileArn(String profileArn) {
            if (profileArn == null || profileArn.trim().isEmpty()) {
                this.profileArn = null;
                return this;
            }
            this.profileArn = ArnValidator.validateProfileArn(profileArn);
            return this;
        }

        /**
         * Sets the profile ARN.
         *
         * @param profileArn The Arn object of the profile
         * @return This builder instance
         */
        public Builder profileArn(Arn profileArn) {
            this.profileArn = profileArn;
            return this;
        }

        /**
         * Sets the role ARN.
         *
         * @param roleArn The ARN string of the role to assume
         * @return This builder instance
         * @throws IllegalArgumentException if the ARN format is invalid
         */
        public Builder roleArn(String roleArn) {
            if (roleArn == null || roleArn.trim().isEmpty()) {
                this.roleArn = null;
                return this;
            }
            this.roleArn = ArnValidator.validateRoleArn(roleArn);
            return this;
        }

        /**
         * Sets the role ARN.
         *
         * @param roleArn The Arn object of the role to assume
         * @return This builder instance
         */
        public Builder roleArn(Arn roleArn) {
            this.roleArn = roleArn;
            return this;
        }

        /**
         * Sets the AWS region.
         *
         * @param region The AWS region for the service endpoint
         * @return This builder instance
         */
        public Builder region(Region region) {
            this.region = region;
            return this;
        }

        /**
         * Sets the role session name.
         *
         * @param roleSessionName The session name for the assumed role
         * @return This builder instance
         */
        public Builder roleSessionName(String roleSessionName) {
            this.roleSessionName = roleSessionName;
            return this;
        }

        /**
         * Sets the duration of the temporary AWS credentials session returned by
         * IAM Roles Anywhere. This controls how long the AWS access key, secret key,
         * and session token remain valid.
         *
         * @param durationSeconds The AWS session duration (900-43200 seconds)
         * @return This builder instance
         */
        public Builder durationSeconds(Integer durationSeconds) {
            this.durationSeconds = durationSeconds;
            return this;
        }

        /**
         * Sets a custom endpoint URI for the IAM Roles Anywhere service.
         *
         * <p>
         * When a custom endpoint is provided, it takes precedence over all other
         * endpoint configuration options (FIPS, dual-stack).
         *
         * @param endpoint The custom endpoint URI
         * @return This builder instance
         */
        public Builder endpoint(URI endpoint) {
            this.customEndpoint = endpoint;
            if (endpoint != null) {
                String scheme = endpoint.getScheme();
                if (scheme != null && !scheme.equalsIgnoreCase("https")) {
                    LOG.warn(() -> "Custom endpoint uses '" + scheme
                            + "' scheme. HTTPS is strongly recommended to protect "
                            + "certificate and credential data in transit. "
                            + "The signed request and AWS credentials response will be "
                            + "sent in plaintext over " + scheme.toUpperCase() + ".");
                }
            }
            return this;
        }

        /**
         * Sets a custom endpoint URI for the IAM Roles Anywhere service.
         *
         * <p>
         * When a custom endpoint is provided, it takes precedence over all other
         * endpoint configuration options (FIPS, dual-stack).
         *
         * @param endpoint The custom endpoint URI as a string
         * @return This builder instance
         * @throws IllegalArgumentException if the string is not a valid URI
         */
        public Builder endpoint(String endpoint) {
            if (endpoint == null) {
                return endpoint((URI) null);
            }
            try {
                return endpoint(URI.create(endpoint));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid endpoint URI: " + endpoint, e);
            }
        }

        /**
         * Enables or disables FIPS endpoints.
         *
         * <p>
         * FIPS endpoints are only available in US regions and AWS GovCloud regions.
         * If FIPS is enabled for a region that doesn't support it, an exception will be
         * thrown during endpoint resolution.
         *
         * <p>
         * This setting is ignored if a custom endpoint is provided.
         *
         * @param fipsEnabled true to use FIPS endpoints, false otherwise
         * @return This builder instance
         */
        public Builder fipsEnabled(boolean fipsEnabled) {
            this.fipsEnabled = fipsEnabled;
            return this;
        }

        /**
         * Enables or disables dual-stack (IPv4/IPv6) endpoints.
         *
         * <p>
         * This setting is ignored if a custom endpoint is provided.
         *
         * @param dualStackEnabled true to use dual-stack endpoints, false otherwise
         * @return This builder instance
         */
        public Builder dualStackEnabled(boolean dualStackEnabled) {
            this.dualStackEnabled = dualStackEnabled;
            return this;
        }

        /**
         * Sets a custom HTTP client for making requests.
         * If not provided, a default Apache HTTP client will be used.
         *
         * @param httpClient The HTTP client to use
         * @return This builder instance
         */
        public Builder httpClient(SdkHttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Defines how early before AWS credential expiration a refresh should be attempted.
         * For example, with a 5-minute stale time and credentials expiring at 2:00 PM,
         * a refresh will be triggered at 1:55 PM. This does NOT affect the X509Identity
         * or how often the identityProvider is called — it only controls when cached
         * AWS credentials (access key, secret key, session token) are considered stale.
         * Must not be a negative duration. Defaults to 5 minutes.
         *
         * @param staleTime duration before AWS credential expiration to trigger refresh
         * @return This builder instance
         */
        public Builder staleTime(Duration staleTime) {
            if (staleTime == null) {
                throw new IllegalArgumentException("staleTime must not be null");
            }
            if (staleTime.isNegative()) {
                throw new IllegalArgumentException("staleTime cannot be a negative duration");
            }
            this.staleTime = staleTime;
            return this;
        }

        /**
         * Sets the minimum interval between credential refresh cycles. Each cycle
         * calls the X509IdentityProvider and the IAM Roles Anywhere service. This
         * prevents retry storms when credentials are expired or the identity provider
         * is failing — even if AWS credentials are stale, a new refresh will not be
         * attempted until this interval has elapsed since the last refresh attempt.
         * Defaults to 5 minutes. Cannot be less than 30 seconds
         * (use Duration.ZERO to disable).
         *
         * @param minRefreshInterval minimum duration between refresh cycles
         * @return This builder instance
         */
        public Builder minRefreshInterval(Duration minRefreshInterval) {
            if (minRefreshInterval == null) {
                throw new IllegalArgumentException("minRefreshInterval must not be null");
            }
            if (!minRefreshInterval.isZero()
                    && minRefreshInterval.compareTo(MIN_REFRESH_INTERVAL_FLOOR) < 0) {
                throw new IllegalArgumentException(
                        "minRefreshInterval cannot be less than "
                        + MIN_REFRESH_INTERVAL_FLOOR.getSeconds() + " seconds"
                        + " (use Duration.ZERO to disable throttling)");
            }
            this.minRefreshInterval = minRefreshInterval;
            return this;
        }

        /**
         * Builds the RolesAnywhereCredentialsProvider instance.
         *
         * @return A configured RolesAnywhereCredentialsProvider
         * @throws IllegalArgumentException if required parameters are missing or
         *                                  invalid
         */
        public RolesAnywhereCredentialsProvider build() {
            region = resolveRegion();
            validateRequiredParameters();
            ValidationUtils.validateSessionDuration(durationSeconds);
            return new RolesAnywhereCredentialsProvider(this);
        }

        private void validateRequiredParameters() {
            ValidationUtils.requireParameter(identityProvider, "X509IdentityProvider");
            ValidationUtils.requireParameter(trustAnchorArn, "Trust anchor ARN");
            ValidationUtils.requireParameter(profileArn, "Profile ARN");
            ValidationUtils.requireParameter(roleArn, "Role ARN");
            // this should never be thrown but is here for sanity checking
            ValidationUtils.requireParameter(region, "Region");
            ValidationUtils.requireParameter(staleTime, "staleTime");
        }
    }
}
