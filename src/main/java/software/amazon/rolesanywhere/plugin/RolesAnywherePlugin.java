package software.amazon.rolesanywhere.plugin;

import java.net.URI;
import java.time.Duration;
import software.amazon.awssdk.annotations.NotThreadSafe;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.annotations.ThreadSafe;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.awscore.AwsServiceClientConfiguration;
import software.amazon.awssdk.core.SdkPlugin;
import software.amazon.awssdk.core.SdkServiceClientConfiguration;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

@SdkPublicApi
@ThreadSafe
public final class RolesAnywherePlugin implements SdkPlugin {
    private final RolesAnywhereCredentialsProvider rolesAnywhereCredentialsProvider;

    private RolesAnywherePlugin(RolesAnywhereCredentialsProvider rolesAnywhereCredentialsProvider) {
        this.rolesAnywhereCredentialsProvider = rolesAnywhereCredentialsProvider;
    }

    @Override
    public void configureClient(SdkServiceClientConfiguration.Builder config) {
        if (!(config instanceof AwsServiceClientConfiguration.Builder)) {
            throw new IllegalStateException("RolesAnywherePlugin can only be applied to AWS service clients, got: "
                    + config.getClass().getName());
        }
        ((AwsServiceClientConfiguration.Builder) config).credentialsProvider(rolesAnywhereCredentialsProvider);
    }

    /**
     * Create a plugin from a pre-built credentials provider. Use this when you
     * already hold a provider (e.g. shared across multiple SDK clients). For
     * fresh construction, use {@link #builder()}.
     */
    public static RolesAnywherePlugin create(RolesAnywhereCredentialsProvider provider) {
        ValidationUtils.requireParameter(provider, "RolesAnywhereCredentialsProvider");
        return new RolesAnywherePlugin(provider);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link RolesAnywherePlugin}. Mirrors every setter on
     * {@link RolesAnywhereCredentialsProvider.Builder}; the underlying provider
     * is constructed at {@link #build()} time and validation flows from there.
     */
    @SdkPublicApi
    @NotThreadSafe
    public static final class Builder {
        private final RolesAnywhereCredentialsProvider.Builder providerBuilder =
                RolesAnywhereCredentialsProvider.builder().source(X509Signer.Source.PLUGIN);

        private Builder() {}

        public Builder identityProvider(X509IdentityProvider identityProvider) {
            providerBuilder.identityProvider(identityProvider);
            return this;
        }

        public Builder trustAnchorArn(String trustAnchorArn) {
            providerBuilder.trustAnchorArn(trustAnchorArn);
            return this;
        }

        public Builder trustAnchorArn(Arn trustAnchorArn) {
            providerBuilder.trustAnchorArn(trustAnchorArn);
            return this;
        }

        public Builder profileArn(String profileArn) {
            providerBuilder.profileArn(profileArn);
            return this;
        }

        public Builder profileArn(Arn profileArn) {
            providerBuilder.profileArn(profileArn);
            return this;
        }

        public Builder roleArn(String roleArn) {
            providerBuilder.roleArn(roleArn);
            return this;
        }

        public Builder roleArn(Arn roleArn) {
            providerBuilder.roleArn(roleArn);
            return this;
        }

        public Builder region(Region region) {
            providerBuilder.region(region);
            return this;
        }

        public Builder roleSessionName(String roleSessionName) {
            providerBuilder.roleSessionName(roleSessionName);
            return this;
        }

        public Builder durationSeconds(Integer durationSeconds) {
            providerBuilder.durationSeconds(durationSeconds);
            return this;
        }

        public Builder endpoint(URI endpoint) {
            providerBuilder.endpoint(endpoint);
            return this;
        }

        public Builder endpoint(String endpoint) {
            providerBuilder.endpoint(endpoint);
            return this;
        }

        public Builder fipsEnabled(boolean fipsEnabled) {
            providerBuilder.fipsEnabled(fipsEnabled);
            return this;
        }

        public Builder dualStackEnabled(boolean dualStackEnabled) {
            providerBuilder.dualStackEnabled(dualStackEnabled);
            return this;
        }

        public Builder httpClient(SdkHttpClient httpClient) {
            providerBuilder.httpClient(httpClient);
            return this;
        }

        public Builder staleTime(Duration staleTime) {
            providerBuilder.staleTime(staleTime);
            return this;
        }

        public Builder minRefreshInterval(Duration minRefreshInterval) {
            providerBuilder.minRefreshInterval(minRefreshInterval);
            return this;
        }

        public RolesAnywherePlugin build() {
            return new RolesAnywherePlugin(providerBuilder.build());
        }
    }
}
