package software.amazon.rolesanywhere.plugin;

import java.net.URI;
import java.time.Duration;
import software.amazon.awssdk.annotations.NotThreadSafe;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.annotations.ThreadSafe;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProviderChain;
import software.amazon.awssdk.awscore.AwsServiceClientConfiguration;
import software.amazon.awssdk.core.SdkPlugin;
import software.amazon.awssdk.core.SdkServiceClientConfiguration;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.identity.spi.IdentityProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.ToString;

@SdkPublicApi
@ThreadSafe
public final class RolesAnywherePlugin implements SdkPlugin {
    private final RolesAnywhereCredentialsProvider rolesAnywhereCredentialsProvider;

    private RolesAnywherePlugin(RolesAnywhereCredentialsProvider rolesAnywhereCredentialsProvider) {
        this.rolesAnywhereCredentialsProvider = rolesAnywhereCredentialsProvider;
    }

    /**
     * Composes {@link RolesAnywhereCredentialsProvider} with any credentials
     * provider the customer already configured on the client. The customer's
     * provider is tried first, ours is the fallback — plugins should add
     * capability, not silently overwrite explicit configuration.
     */
    @Override
    public void configureClient(SdkServiceClientConfiguration.Builder config) {
        if (!(config instanceof AwsServiceClientConfiguration.Builder)) {
            throw new IllegalStateException("RolesAnywherePlugin can only be applied to AWS service clients, got: "
                    + config.getClass().getName());
        }
        AwsServiceClientConfiguration.Builder awsConfig = (AwsServiceClientConfiguration.Builder) config;
        IdentityProvider<? extends AwsCredentialsIdentity> existing = awsConfig.credentialsProvider();
        if (existing == null) {
            awsConfig.credentialsProvider(rolesAnywhereCredentialsProvider);
        } else {
            awsConfig.credentialsProvider(AwsCredentialsProviderChain.builder()
                    .credentialsIdentityProviders(java.util.Arrays.asList(existing, rolesAnywhereCredentialsProvider))
                    .build());
        }
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

    @Override
    public String toString() {
        return ToString.builder("RolesAnywherePlugin")
                .add("credentialsProvider", rolesAnywhereCredentialsProvider)
                .build();
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

        public Builder fipsEnabled(Boolean fipsEnabled) {
            providerBuilder.fipsEnabled(fipsEnabled);
            return this;
        }

        public Builder dualStackEnabled(Boolean dualStackEnabled) {
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
