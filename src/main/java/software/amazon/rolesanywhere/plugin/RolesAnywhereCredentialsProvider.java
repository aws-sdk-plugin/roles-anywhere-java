package software.amazon.rolesanywhere.plugin;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import software.amazon.awssdk.annotations.NotThreadSafe;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.annotations.ThreadSafe;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.Logger;
import software.amazon.awssdk.utils.SdkAutoCloseable;
import software.amazon.awssdk.utils.ToString;
import software.amazon.awssdk.utils.cache.CachedSupplier;
import software.amazon.awssdk.utils.cache.NonBlocking;
import software.amazon.awssdk.utils.cache.RefreshResult;

/**
 * AWS Credentials Provider for IAM Roles Anywhere.
 * This provider obtains temporary credentials using IAM Roles Anywhere service.
 *
 * <p>
 * Caching and refresh are delegated to {@link CachedSupplier} from the AWS SDK,
 * the same primitive that backs {@code InstanceProfileCredentialsProvider},
 * {@code ContainerCredentialsProvider}, and {@code StsCredentialsProvider}.
 * {@code CachedSupplier}, {@link RefreshResult}, {@link NonBlocking}, and
 * {@code StaleValueBehavior} are annotated {@code @SdkProtectedApi} — semi-stable
 * across SDK minor versions. We accept that contract because every SDK-provided
 * credentials provider relies on it, which gives the SDK team strong incentive
 * not to break it; if it ever does shift, this class fails at compile time
 * during a BOM bump rather than silently.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * // Create the provider — load certificate and key inside the lambda to minimize
 * // the time the private key is held in memory
 * RolesAnywhereCredentialsProvider rolesAnywhereCredProvider = RolesAnywhereCredentialsProvider.builder()
 *         .profileArn(PROFILE_ARN)
 *         .roleArn(ROLE_ARN)
 *         .trustAnchorArn(TRUST_ANCHOR_ARN)
 *         .identityProvider(X509IdentityProvider.fromFiles(certPath, keyPath, "RSA"))
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
@SdkPublicApi
@ThreadSafe
public final class RolesAnywhereCredentialsProvider implements AwsCredentialsProvider, SdkAutoCloseable {
    private static final Logger LOG = Logger.loggerFor(RolesAnywhereCredentialsProvider.class);

    // HTTP client configuration
    private static final Duration DEFAULT_CONNECTION_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_SOCKET_TIMEOUT = Duration.ofSeconds(30);

    // Credential refresh configuration
    private static final Duration DEFAULT_MIN_REFRESH_INTERVAL = Duration.ofMinutes(5);
    private static final Duration MIN_REFRESH_INTERVAL_FLOOR = Duration.ofSeconds(30);
    private static final String REFRESH_THREAD_NAME = "rolesanywhere-credentials-refresh";

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
    private final Boolean fipsEnabled;
    private final Boolean dualStackEnabled;
    private final SdkHttpClient httpClient;
    private final boolean ownedHttpClient;

    // Caller-facing surface tag emitted in the User-Agent — set to PLUGIN by
    // RolesAnywherePlugin.Builder, PROVIDER for direct provider usage.
    private final X509Signer.Source source;

    // Credential cache and refresh settings
    private final Duration staleTime;
    private final Duration minRefreshInterval;
    private final CachedSupplier<AwsCredentials> credentialsCache;

    // Throttle state — guards the refresh function so a failing supplier cannot
    // burn the network at the rate CachedSupplier asks for. CachedSupplier uses
    // a tryLock(5s) around supplier invocation, so concurrent calls into the
    // refresh function are rare-but-possible if a refresh runs longer than 5s
    // (network I/O can). volatile gives visibility; the read-modify-write race
    // can let two refreshes through instead of one — benign, since the worst
    // case is a single redundant network call, which the throttle exists to
    // prevent at scale rather than absolutely.
    private volatile Instant lastRefreshAttempt = Instant.EPOCH;

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
            this.ownedHttpClient = false;
        } else {
            this.httpClient = createDefaultHttpClient();
            this.ownedHttpClient = true;
        }
        this.staleTime = builder.staleTime;
        this.minRefreshInterval = builder.minRefreshInterval;
        this.source = builder.source;
        // StaleValueBehavior.ALLOW is the static-stability mode: when refresh fails
        // past staleTime, the previously-cached value is still served (with jittered
        // backoff). The default STRICT would throw, which is the opposite of what
        // IAM Roles Anywhere wants — service-side enforcement is the source of truth
        // for credential validity.
        this.credentialsCache = CachedSupplier.builder(this::refreshCredentials)
                .prefetchStrategy(new NonBlocking(REFRESH_THREAD_NAME))
                .staleValueBehavior(CachedSupplier.StaleValueBehavior.ALLOW)
                .build();
    }

    /**
     * Creates a new builder for RolesAnywhereCredentialsProvider.
     *
     * @return A new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    private X509Identity resolveX509Identity() {
        X509Identity resolved = identityProvider.resolve();
        if (resolved == null) {
            throw SdkClientException.create("X509IdentityProvider returned null. "
                    + "Ensure your identityProvider returns a valid X509Identity.");
        }
        try {
            ValidationUtils.validateCertificate(resolved.certificate());
            ValidationUtils.validatePrivateKey(resolved.privateKey());
        } catch (Exception e) {
            throw SdkClientException.create("X509IdentityProvider returned invalid key material", e);
        }
        Instant expiryHorizon = Instant.now().plus(Duration.ofDays(30));
        warnIfExpiringSoon(resolved.certificate(), "leaf", expiryHorizon);
        int index = 0;
        for (X509Certificate intermediate : resolved.certificateChain()) {
            warnIfExpiringSoon(intermediate, "chain[" + index + "]", expiryHorizon);
            index++;
        }
        return resolved;
    }

    private void warnIfExpiringSoon(X509Certificate cert, String label, Instant horizon) {
        Instant notAfter = cert.getNotAfter().toInstant();
        if (horizon.isAfter(notAfter)) {
            LOG.warn(() -> "X.509 certificate (" + label
                    + ", subject=" + cert.getSubjectX500Principal().getName()
                    + ") expires within 30 days (at " + notAfter + "). "
                    + "Rotate your certificate to avoid authentication failures.");
        }
    }

    /**
     * Resolves AWS credentials for IAM Roles Anywhere. Delegates entirely to
     * {@link CachedSupplier}; cache state, refresh scheduling, concurrency,
     * and stale-value handling all live there.
     *
     * @throws SdkClientException if the initial refresh cannot produce
     *         credentials — for example, the {@link X509IdentityProvider}
     *         throws, signing fails, the {@code CreateSession} HTTP request
     *         errors out, the service returns a non-2xx response, or the
     *         refresh throttle rejects a retry on cold start with no cached
     *         value. Once a refresh succeeds, subsequent stale-value failures
     *         are absorbed by {@code StaleValueBehavior.ALLOW} and the last
     *         known good credentials are returned instead of throwing.
     */
    @Override
    public AwsCredentials resolveCredentials() {
        return credentialsCache.get();
    }

    /**
     * Refresh function handed to {@link CachedSupplier}. Returns a
     * {@link RefreshResult} whose {@code prefetchTime} is the expiration minus
     * the configured {@code staleTime} (background refresh kicks off there) and
     * whose {@code staleTime} is the credential expiration itself. Past that,
     * {@code StaleValueBehavior.ALLOW} keeps serving the cached value while we
     * keep retrying — the service is the source of truth for expiry.
     *
     * <p>The {@code minRefreshInterval} throttle is enforced here: if a refresh
     * attempt fails inside the throttle window, we throw, and the cache (under
     * {@code ALLOW}) serves the stale value instead of pounding the network.
     */
    private RefreshResult<AwsCredentials> refreshCredentials() {
        Instant now = Instant.now();
        Instant nextAllowedRefresh = lastRefreshAttempt.plus(minRefreshInterval);
        if (now.isBefore(nextAllowedRefresh)) {
            throw SdkClientException.create("Refresh throttled — minimum refresh interval " + minRefreshInterval
                    + " not yet elapsed since last refresh attempt at " + lastRefreshAttempt + ".");
        }
        lastRefreshAttempt = now;

        X509Signer signer = X509Signer.builder()
                .region(this.region)
                .serviceName("rolesanywhere")
                .source(this.source)
                .build();
        SdkHttpFullRequest request = this.createSessionRequestBuilder().build();
        X509Identity keyMaterial = this.resolveX509Identity();
        SignedRequest sr;
        try {
            sr = signer.sign(request, keyMaterial);
        } finally {
            // Best-effort zero of JCE-internal private key state on providers
            // that honor Destroyable. No-op when the customer owns the key
            // (see X509Identity.create vs create).
            keyMaterial.destroyIfOwned();
        }
        String responseBody = CreateSessionRequestUtils.executeHttpRequest(request, sr, this.httpClient);
        AwsCredentials credentials = CreateSessionRequestUtils.parseCreateSessionResponse(responseBody);

        Instant expiration = credentials.expirationTime().orElse(null);
        if (expiration == null) {
            // Service always returns an expiration; absence is a contract violation.
            throw SdkClientException.create("IAM Roles Anywhere returned credentials with no expiration time.");
        }
        Instant prefetch = expiration.minus(staleTime);
        return RefreshResult.builder(credentials)
                .prefetchTime(prefetch)
                .staleTime(expiration)
                .build();
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
                .fipsEnabled(Boolean.TRUE.equals(fipsEnabled))
                .dualStackEnabled(Boolean.TRUE.equals(dualStackEnabled));

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
     * Releases resources owned by this provider: the {@link CachedSupplier}'s
     * background refresh thread is always closed; the HTTP client is closed
     * only when the provider created it (per {@code PBP_JAVA_CLOSE_IFF_OWNED}).
     */
    @Override
    public void close() {
        credentialsCache.close();
        if (ownedHttpClient) {
            httpClient.close();
        }
    }

    @Override
    public String toString() {
        return ToString.builder("RolesAnywhereCredentialsProvider")
                .add("region", region)
                .add("profileArn", profileArn)
                .add("roleArn", roleArn)
                .add("trustAnchorArn", trustAnchorArn)
                .add("roleSessionName", roleSessionName)
                .add("durationSeconds", durationSeconds)
                .add("customEndpoint", customEndpoint)
                .add("fipsEnabled", fipsEnabled)
                .add("dualStackEnabled", dualStackEnabled)
                .add("staleTime", staleTime)
                .add("minRefreshInterval", minRefreshInterval)
                .build();
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
     * All functions on this {@link Builder} should also be present on the {@link RolesAnywherePlugin.Builder} class.
     */
    @SdkPublicApi
    @NotThreadSafe
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
        private Boolean fipsEnabled;
        private Boolean dualStackEnabled;
        private SdkHttpClient httpClient;

        // Credential cache and refresh settings
        private Duration staleTime = Duration.ofMinutes(5);
        private Duration minRefreshInterval = DEFAULT_MIN_REFRESH_INTERVAL;

        // User-Agent source tag — package-private setter used by
        // RolesAnywherePlugin.Builder to distinguish plugin vs. direct usage.
        private X509Signer.Source source = X509Signer.Source.PROVIDER;

        private Builder() {}

        /**
         * Overrides the User-Agent source tag. Package-private: only
         * {@link RolesAnywherePlugin.Builder} calls this to mark plugin-driven
         * traffic. Customers using this builder directly always emit
         * {@code provider}.
         */
        Builder source(X509Signer.Source source) {
            this.source = source;
            return this;
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
         * Sets the {@link X509IdentityProvider} that supplies signing key
         * material on every credential refresh.
         *
         * @param identityProvider provider of X.509 signing key material
         * @return This builder instance
         * @throws IllegalArgumentException if {@code identityProvider} is null
         */
        public Builder identityProvider(X509IdentityProvider identityProvider) {
            ValidationUtils.requireParameter(identityProvider, "X509IdentityProvider");
            this.identityProvider = identityProvider;
            return this;
        }

        /**
         * Sets the trust anchor ARN.
         *
         * @param trustAnchorArn The ARN string of the trust anchor
         * @return This builder instance
         * @throws IllegalArgumentException if {@code trustAnchorArn} is null, blank,
         *                                  or not a valid trust anchor ARN
         */
        public Builder trustAnchorArn(String trustAnchorArn) {
            ValidationUtils.requireNonNullAndNonEmpty(trustAnchorArn, "Trust anchor ARN");
            this.trustAnchorArn = ArnValidator.validateTrustAnchorArn(trustAnchorArn);
            return this;
        }

        /**
         * Sets the trust anchor ARN.
         *
         * @param trustAnchorArn The Arn object of the trust anchor
         * @return This builder instance
         * @throws IllegalArgumentException if {@code trustAnchorArn} is null
         */
        public Builder trustAnchorArn(Arn trustAnchorArn) {
            ValidationUtils.requireParameter(trustAnchorArn, "Trust anchor ARN");
            this.trustAnchorArn = trustAnchorArn;
            return this;
        }

        /**
         * Sets the profile ARN.
         *
         * @param profileArn The ARN string of the profile
         * @return This builder instance
         * @throws IllegalArgumentException if {@code profileArn} is null, blank, or
         *                                  not a valid profile ARN
         */
        public Builder profileArn(String profileArn) {
            ValidationUtils.requireNonNullAndNonEmpty(profileArn, "Profile ARN");
            this.profileArn = ArnValidator.validateProfileArn(profileArn);
            return this;
        }

        /**
         * Sets the profile ARN.
         *
         * @param profileArn The Arn object of the profile
         * @return This builder instance
         * @throws IllegalArgumentException if {@code profileArn} is null
         */
        public Builder profileArn(Arn profileArn) {
            ValidationUtils.requireParameter(profileArn, "Profile ARN");
            this.profileArn = profileArn;
            return this;
        }

        /**
         * Sets the role ARN.
         *
         * @param roleArn The ARN string of the role to assume
         * @return This builder instance
         * @throws IllegalArgumentException if {@code roleArn} is null, blank, or
         *                                  not a valid role ARN
         */
        public Builder roleArn(String roleArn) {
            ValidationUtils.requireNonNullAndNonEmpty(roleArn, "Role ARN");
            this.roleArn = ArnValidator.validateRoleArn(roleArn);
            return this;
        }

        /**
         * Sets the role ARN.
         *
         * @param roleArn The Arn object of the role to assume
         * @return This builder instance
         * @throws IllegalArgumentException if {@code roleArn} is null
         */
        public Builder roleArn(Arn roleArn) {
            ValidationUtils.requireParameter(roleArn, "Role ARN");
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
         * Sets the role session name. Pass {@code null} to clear a previously-set
         * value and let the IAM Roles Anywhere service pick a default; do not pass
         * an empty or whitespace-only string.
         *
         * @param roleSessionName The session name for the assumed role, or null to
         *                        let the service choose
         * @return This builder instance
         * @throws IllegalArgumentException if {@code roleSessionName} is non-null
         *                                  and blank
         */
        public Builder roleSessionName(String roleSessionName) {
            if (roleSessionName != null && roleSessionName.trim().isEmpty()) {
                throw new IllegalArgumentException("roleSessionName cannot be empty or whitespace-only "
                        + "(pass null to use the service default)");
            }
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
         * Sets a custom endpoint URI for the IAM Roles Anywhere service. Pass
         * {@code null} to clear a previously-set value and fall back to
         * region/FIPS/dual-stack-derived endpoint resolution.
         *
         * <p>
         * When a custom endpoint is provided, it takes precedence over all other
         * endpoint configuration options (FIPS, dual-stack).
         *
         * @param endpoint The custom endpoint URI, or null to use derived resolution
         * @return This builder instance
         * @throws IllegalArgumentException if {@code endpoint} is non-null and has
         *                                  no host (e.g., {@code URI.create("")})
         */
        public Builder endpoint(URI endpoint) {
            if (endpoint != null) {
                if (endpoint.getHost() == null) {
                    throw new IllegalArgumentException("Custom endpoint URI must have a host, got: " + endpoint);
                }
                String scheme = endpoint.getScheme();
                if (scheme != null && !scheme.equalsIgnoreCase("https")) {
                    LOG.warn(() -> "Custom endpoint uses '" + scheme
                            + "' scheme. HTTPS is strongly recommended to protect "
                            + "certificate and credential data in transit. "
                            + "The signed request and AWS credentials response will be "
                            + "sent in plaintext over " + scheme.toUpperCase(Locale.ROOT) + ".");
                }
            }
            this.customEndpoint = endpoint;
            return this;
        }

        /**
         * Sets a custom endpoint URI for the IAM Roles Anywhere service. Pass
         * {@code null} to clear a previously-set value and fall back to
         * region/FIPS/dual-stack-derived endpoint resolution.
         *
         * <p>
         * When a custom endpoint is provided, it takes precedence over all other
         * endpoint configuration options (FIPS, dual-stack).
         *
         * @param endpoint The custom endpoint URI as a string, or null to use
         *                 derived resolution
         * @return This builder instance
         * @throws IllegalArgumentException if {@code endpoint} is blank, not a
         *                                  valid URI, or has no host
         */
        public Builder endpoint(String endpoint) {
            if (endpoint == null) {
                return endpoint((URI) null);
            }
            if (endpoint.trim().isEmpty()) {
                throw new IllegalArgumentException("endpoint cannot be empty or whitespace-only (pass null to clear)");
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
         * @param fipsEnabled {@code true} to use FIPS endpoints, {@code false} to
         *                    explicitly opt out, or {@code null} to leave
         *                    unconfigured (endpoint resolution falls back to the
         *                    region default, which is currently non-FIPS)
         * @return This builder instance
         */
        public Builder fipsEnabled(Boolean fipsEnabled) {
            this.fipsEnabled = fipsEnabled;
            return this;
        }

        /**
         * Enables or disables dual-stack (IPv4/IPv6) endpoints.
         *
         * <p>
         * This setting is ignored if a custom endpoint is provided.
         *
         * @param dualStackEnabled {@code true} to use dual-stack endpoints,
         *                         {@code false} to explicitly opt out, or
         *                         {@code null} to leave unconfigured (endpoint
         *                         resolution falls back to the region default)
         * @return This builder instance
         */
        public Builder dualStackEnabled(Boolean dualStackEnabled) {
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
         * Defines how early before AWS credential expiration a background refresh
         * should be attempted. With a 5-minute stale time and credentials expiring
         * at 2:00 PM, the background refresh starts at 1:55 PM. Maps to
         * {@link RefreshResult}'s {@code prefetchTime} (= expiration − staleTime);
         * the credentials' {@code expirationTime} itself is the {@code staleTime}
         * passed to {@link CachedSupplier}. Must not be negative. Defaults to 5
         * minutes.
         *
         * @param staleTime duration before AWS credential expiration to trigger refresh
         * @return This builder instance
         * @throws IllegalArgumentException if {@code staleTime} is {@code null}
         *         or a negative duration.
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
         * Sets the minimum interval between credential refresh attempts. This
         * prevents retry storms when the X509IdentityProvider or the IAM Roles
         * Anywhere service is failing — even if AWS credentials are stale, a new
         * refresh is not attempted until this interval has elapsed since the last
         * attempt. Defaults to 5 minutes. Cannot be less than 30 seconds (use
         * Duration.ZERO to disable).
         *
         * <p>The throttle is enforced inside the refresh function handed to
         * {@link CachedSupplier}: throttled attempts throw, and {@code
         * StaleValueBehavior.ALLOW} causes the cache to keep serving the
         * previously-cached credentials. On cold start with no cached value, a
         * throttled attempt propagates as {@link SdkClientException}.
         *
         * @param minRefreshInterval minimum duration between refresh attempts
         * @return This builder instance
         * @throws IllegalArgumentException if {@code minRefreshInterval} is
         *         {@code null} or is non-zero and less than the 30-second
         *         floor. Use {@link Duration#ZERO} to disable throttling.
         */
        @SuppressWarnings("JavaDurationGetSecondsToToSeconds") // getSeconds() is Java 8; toSeconds() is Java 9+
        public Builder minRefreshInterval(Duration minRefreshInterval) {
            if (minRefreshInterval == null) {
                throw new IllegalArgumentException("minRefreshInterval must not be null");
            }
            if (!minRefreshInterval.isZero() && minRefreshInterval.compareTo(MIN_REFRESH_INTERVAL_FLOOR) < 0) {
                throw new IllegalArgumentException("minRefreshInterval cannot be less than "
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
         * @throws IllegalArgumentException if a required parameter setter was
         *                                  never called, or if durationSeconds is
         *                                  outside the valid range
         */
        public RolesAnywhereCredentialsProvider build() {
            region = resolveRegion();
            // Setters reject bad input, so the only way these are still null is
            // that the customer never called the setter. Surface that with a
            // clear message rather than letting a NullPointerException leak out
            // of the constructor or refresh function.
            ValidationUtils.requireParameter(identityProvider, "X509IdentityProvider");
            ValidationUtils.requireParameter(trustAnchorArn, "Trust anchor ARN");
            ValidationUtils.requireParameter(profileArn, "Profile ARN");
            ValidationUtils.requireParameter(roleArn, "Role ARN");
            // region is set by resolveRegion() above; this is a sanity check.
            ValidationUtils.requireParameter(region, "Region");
            // staleTime has a default and the setter rejects null, so this
            // can only fail through reflection. Sanity check.
            ValidationUtils.requireParameter(staleTime, "staleTime");
            ValidationUtils.validateSessionDuration(durationSeconds);
            return new RolesAnywhereCredentialsProvider(this);
        }
    }
}
