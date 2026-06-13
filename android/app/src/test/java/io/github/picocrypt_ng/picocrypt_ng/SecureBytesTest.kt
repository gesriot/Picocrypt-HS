package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class SecureBytesTest {
    @Test
    fun `ascii password encodes to UTF-8 matching String getBytes`() {
        val pw = "hunter2".toCharArray()
        assertArrayEquals("hunter2".toByteArray(Charsets.UTF_8), pw.toUtf8BytesSecure())
    }

    @Test
    fun `multibyte password matches legacy String UTF-8 path (interop)`() {
        // Locks byte-for-byte compatibility with the desktop/CLI String(password)->UTF-8 path.
        val pw = "pä€🔒".toCharArray() // includes 2-byte, 3-byte, and a surrogate-pair 4-byte char
        assertArrayEquals("pä€🔒".toByteArray(Charsets.UTF_8), pw.toUtf8BytesSecure())
    }

    @Test
    fun `empty password encodes to empty array`() {
        assertArrayEquals(ByteArray(0), CharArray(0).toUtf8BytesSecure())
    }
}
