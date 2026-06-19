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

public class X509IdentityProviderTest {

    // Happy path — provider returns valid identity
    @Test
    public void testGetIdentityReturnsValidIdentity() throws Exception {
        X509Identity expected = createTestIdentity();
        X509IdentityProvider provider = () -> expected;

        X509Identity result = provider.create();

        assertNotNull(result);
        assertEquals(expected.certificate(), result.certificate());
        assertEquals(expected.privateKey(), result.privateKey());
    }

    // Refresh — provider returns new identity on each call (cert rotation)
    @Test
    public void testGetIdentityReturnsFreshIdentityOnEachCall() throws Exception {
        X509Identity identity1 = createTestIdentity();
        X509Identity identity2 = createTestIdentity();
        AtomicInteger callCount = new AtomicInteger(0);

        X509IdentityProvider provider = () -> {
            if (callCount.getAndIncrement() == 0) {
                return identity1;
            }
            return identity2;
        };

        assertEquals(identity1, provider.create());
        assertEquals(identity2, provider.create());
    }

    // Null return — should fail clearly downstream
    @Test
    public void testGetIdentityReturnsNullHandledGracefully() throws Exception {
        X509IdentityProvider provider = () -> null;

        assertNull(provider.create());
    }

    // Exception propagation — provider throws at runtime
    @Test
    public void testGetIdentityThrowsExceptionPropagates() {
        X509IdentityProvider provider = () -> {
            throw new IdentityProviderException("cert store unavailable");
        };

        assertThrows(IdentityProviderException.class, provider::create);
    }

    // Thread safety — concurrent calls to a stateful provider don't corrupt state
    @Test
    public void testGetIdentityConcurrentAccessNoCorruption() throws Exception {
        X509Identity identity1 = createTestIdentity();
        X509Identity identity2 = createTestIdentity();
        AtomicInteger counter = new AtomicInteger(0);

        // Stateful provider that rotates between two identities
        X509IdentityProvider provider = () -> {
            if (counter.getAndIncrement() % 2 == 0) {
                return identity1;
            }
            return identity2;
        };

        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        X509Identity[] results = new X509Identity[threadCount];
        for (int i = 0; i < threadCount; i++) {
            int index = i;
            threads[i] = new Thread(() -> {
                try {
                    results[index] = provider.create();
                } catch (IdentityProviderException e) {
                    throw new RuntimeException(e);
                }
            });
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

    private X509Identity createTestIdentity() throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        PrivateKey privateKey =
                KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
        return new X509Identity(certificate, privateKey);
    }
}
