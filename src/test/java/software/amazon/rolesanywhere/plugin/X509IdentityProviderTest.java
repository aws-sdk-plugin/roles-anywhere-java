package software.amazon.rolesanywhere.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;

public class X509IdentityProviderTest {

    @Test
    public void testResolveReturnsValidKeyMaterial() throws Exception {
        X509Identity expected = createTestKeyMaterial();
        X509IdentityProvider provider = () -> expected;

        X509Identity result = provider.resolve();

        assertNotNull(result);
        assertEquals(expected.certificate(), result.certificate());
        assertEquals(expected.privateKey(), result.privateKey());
    }

    @Test
    public void testResolveReturnsFreshKeyMaterialOnEachCall() throws Exception {
        X509Identity km1 = createTestKeyMaterial();
        X509Identity km2 = createTestKeyMaterial();
        AtomicInteger callCount = new AtomicInteger(0);

        X509IdentityProvider provider = () -> callCount.getAndIncrement() == 0 ? km1 : km2;

        assertEquals(km1, provider.resolve());
        assertEquals(km2, provider.resolve());
    }

    @Test
    public void testResolveNullReturnedByProvider() {
        X509IdentityProvider provider = () -> null;
        assertNull(provider.resolve());
    }

    @Test
    public void testResolveThrowsSdkClientException() {
        X509IdentityProvider provider = () -> {
            throw SdkClientException.create("cert store unavailable");
        };

        assertThrows(SdkClientException.class, provider::resolve);
    }

    @Test
    public void testResolveConcurrentAccessNoCorruption() throws Exception {
        X509Identity km1 = createTestKeyMaterial();
        X509Identity km2 = createTestKeyMaterial();
        AtomicInteger counter = new AtomicInteger(0);

        X509IdentityProvider provider = () -> counter.getAndIncrement() % 2 == 0 ? km1 : km2;

        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        X509Identity[] results = new X509Identity[threadCount];
        for (int i = 0; i < threadCount; i++) {
            int index = i;
            threads[i] = new Thread(() -> results[index] = provider.resolve());
            threads[i].start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        for (X509Identity result : results) {
            assertNotNull(result);
        }
        assertEquals(threadCount, counter.get());
    }

    @Test
    public void testOfStaticReturnsSameIdentityEveryTime() throws Exception {
        X509Identity km = createTestKeyMaterial();
        X509IdentityProvider provider = X509IdentityProvider.ofStatic(km);

        X509Identity first = provider.resolve();
        X509Identity second = provider.resolve();
        assertEquals(first, second);
        assertEquals(km.certificate(), first.certificate());
        assertEquals(km.privateKey(), first.privateKey());
    }

    private X509Identity createTestKeyMaterial() throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        PrivateKey privateKey =
                KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
        return X509Identity.create(certificate, privateKey);
    }
}
