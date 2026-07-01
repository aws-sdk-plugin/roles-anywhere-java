package software.amazon.rolesanywhere.plugin;

import java.util.Arrays;
import software.amazon.awssdk.annotations.SdkInternalApi;

/**
 * Best-effort utility for clearing sensitive data from memory.
 *
 * <p>The JVM's JIT compiler (C2, Graal) may optimize away {@link Arrays#fill}
 * on arrays that have no subsequent reads — a dead-store elimination. This class
 * uses {@link VarHandle#fullFence()} to prevent the compiler from eliding the
 * zeroing operation.</p>
 *
 * <p><strong>Important:</strong> These methods are best-effort only. The JVM may have already
 * copied or relocated the sensitive data (e.g., during GC compaction, JIT deoptimization,
 * or internal String/array operations) before the clear is invoked. Callers should not
 * assume that sensitive data is fully erased from process memory after calling these methods.</p>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * char[] password = getPasswordFromVault();
 * try {
 *     PrivateKey pk = CertificateUtils.loadPrivateKey(keyPath, "RSA", password);
 *     // use pk...
 * } finally {
 *     SecurityUtils.clear(password);
 * }
 * }</pre>
 */
@SdkInternalApi
final class SecurityUtils {

    // Volatile write acts as a StoreLoad barrier on all JVMs, preventing the JIT
    // from eliminating the preceding Arrays.fill as a dead store. Cheaper than
    // synchronized and available on Java 8+ (unlike java.lang.invoke.VarHandle,
    // which is Java 9+).
    @SuppressWarnings("unused")
    private static volatile int fence;

    private SecurityUtils() {
        // Utility class
    }

    /**
     * Best-effort zeroing of a char array that resists JIT dead-store elimination.
     *
     * <p>This method cannot guarantee that all copies of the sensitive data are erased.
     * The JVM may have moved or copied the underlying data (e.g., during GC compaction
     * or JIT deoptimization) before this method is called. Only the contents at the
     * current array address are zeroed.</p>
     *
     * @param sensitive the char array to clear, may be null (no-op)
     */
    public static void clear(char[] sensitive) {
        if (sensitive != null) {
            Arrays.fill(sensitive, '\0');
            fence = 0;
        }
    }

    /**
     * Best-effort zeroing of a byte array that resists JIT dead-store elimination.
     *
     * <p>Useful for clearing intermediate DER-encoded key bytes after decryption.
     * This method cannot guarantee that all copies of the sensitive data are erased.
     * The JVM may have moved or copied the underlying data (e.g., during GC compaction
     * or JIT deoptimization) before this method is called. Only the contents at the
     * current array address are zeroed.</p>
     *
     * @param sensitive the byte array to clear, may be null (no-op)
     */
    public static void clear(byte[] sensitive) {
        if (sensitive != null) {
            Arrays.fill(sensitive, (byte) 0);
            fence = 0;
        }
    }
}
