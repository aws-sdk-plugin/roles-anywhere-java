package software.amazon.rolesanywhere.plugin;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.AwsServiceClientConfiguration;
import software.amazon.awssdk.core.SdkServiceClientConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rolesanywhere.RolesAnywhereServiceClientConfiguration;

class RolesAnywherePluginTest {

    @Test
    void configureClient_awsClient_setsCredentialsProvider() {
        RolesAnywhereCredentialsProvider provider = mock(RolesAnywhereCredentialsProvider.class);
        RolesAnywherePlugin plugin = RolesAnywherePlugin.create(provider);
        AwsServiceClientConfiguration.Builder awsConfig = mock(AwsServiceClientConfiguration.Builder.class);

        plugin.configureClient(awsConfig);

        verify(awsConfig).credentialsProvider(provider);
    }

    @Test
    void configureClient_nonAwsClient_throwsAndDoesNotMutateConfig() {
        RolesAnywherePlugin plugin = RolesAnywherePlugin.create(mock(RolesAnywhereCredentialsProvider.class));
        SdkServiceClientConfiguration.Builder nonAwsConfig = mock(SdkServiceClientConfiguration.Builder.class);

        IllegalStateException ex =
                assertThrows(IllegalStateException.class, () -> plugin.configureClient(nonAwsConfig));

        assertTrue(ex.getMessage().contains("RolesAnywherePlugin can only be applied to AWS service clients"));
        assertTrue(
                ex.getMessage().contains(nonAwsConfig.getClass().getName()),
                "Error message should include the actual config class name; was: " + ex.getMessage());
        verifyNoInteractions(nonAwsConfig);
    }

    @Test
    void plugin_andDirectSetter_resolveToSameCredentialsProvider() {
        RolesAnywhereCredentialsProvider provider = mock(RolesAnywhereCredentialsProvider.class);

        AwsServiceClientConfiguration.Builder viaPlugin = RolesAnywhereServiceClientConfiguration.builder();
        RolesAnywherePlugin.create(provider).configureClient(viaPlugin);

        AwsServiceClientConfiguration.Builder viaDirect = RolesAnywhereServiceClientConfiguration.builder();
        viaDirect.credentialsProvider(provider);

        assertSame(provider, viaPlugin.credentialsProvider());
        assertSame(viaPlugin.credentialsProvider(), viaDirect.credentialsProvider());
    }

    @Test
    void create_nullProvider_throws() {
        assertThrows(IllegalArgumentException.class, () -> RolesAnywherePlugin.create(null));
    }

    @Test
    void builder_endToEnd_producesPluginEquivalentToProviderBuilder() {
        // The plugin's builder is meant to be a superset of the provider's builder:
        // calling the same setters on both should yield interchangeable plugins.
        X509IdentityProvider identityProvider = mock(X509IdentityProvider.class);
        String trustAnchor =
                "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/00000000-0000-0000-0000-000000000000";
        String profile = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/00000000-0000-0000-0000-000000000000";
        String role = "arn:aws:iam::123456789012:role/TestRole";

        RolesAnywhereCredentialsProvider directProvider = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(identityProvider)
                .trustAnchorArn(trustAnchor)
                .profileArn(profile)
                .roleArn(role)
                .region(Region.US_EAST_1)
                .build();

        RolesAnywherePlugin viaPluginBuilder = RolesAnywherePlugin.builder()
                .identityProvider(identityProvider)
                .trustAnchorArn(trustAnchor)
                .profileArn(profile)
                .roleArn(role)
                .region(Region.US_EAST_1)
                .build();

        AwsServiceClientConfiguration.Builder a = RolesAnywhereServiceClientConfiguration.builder();
        AwsServiceClientConfiguration.Builder b = RolesAnywhereServiceClientConfiguration.builder();
        RolesAnywherePlugin.create(directProvider).configureClient(a);
        viaPluginBuilder.configureClient(b);

        // Both code paths produced *some* provider on their respective configs.
        // We can't assertSame the providers (they're different instances), but
        // we can verify both are non-null and have the same concrete type.
        assertSame(directProvider.getClass(), a.credentialsProvider().getClass());
        assertSame(directProvider.getClass(), b.credentialsProvider().getClass());
    }

    @Test
    void builder_missingRequiredArgs_throwsViaProviderValidation() {
        // The plugin builder must not silently produce an under-configured provider.
        assertThrows(
                IllegalArgumentException.class,
                () -> RolesAnywherePlugin.builder().build());
    }
}
