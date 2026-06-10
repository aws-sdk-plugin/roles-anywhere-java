package software.amazon.awssdk.services.rolesanywhere.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SecurityUtils} zeroization methods.
 */
class SecurityUtilsTest {

    @Test
    void clearByteArrayZeroesContents() {
        byte[] sensitive = {1, 2, 3, 4, 5};
        SecurityUtils.clear(sensitive);
        assertArrayEquals(new byte[5], sensitive);
    }

    @Test
    void clearCharArrayZeroesContents() {
        char[] sensitive = {'s', 'e', 'c', 'r', 'e', 't'};
        SecurityUtils.clear(sensitive);
        assertArrayEquals(new char[6], sensitive);
    }

    @Test
    void clearNullByteArrayDoesNotThrow() {
        assertDoesNotThrow(() -> SecurityUtils.clear((byte[]) null));
    }

    @Test
    void clearNullCharArrayDoesNotThrow() {
        assertDoesNotThrow(() -> SecurityUtils.clear((char[]) null));
    }

    @Test
    void clearEmptyByteArrayDoesNotThrow() {
        assertDoesNotThrow(() -> SecurityUtils.clear(new byte[0]));
    }

    @Test
    void clearEmptyCharArrayDoesNotThrow() {
        assertDoesNotThrow(() -> SecurityUtils.clear(new char[0]));
    }
}
