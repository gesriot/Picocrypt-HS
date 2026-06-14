package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.json.JSONException
import org.json.JSONObject

/**
 * Unit tests for GoBridge.
 *
 * Two kinds of tests live here:
 *  - Pure-logic tests (request-JSON building, response parsing, password zeroing, option
 *    defaults) run on the plain JVM and assert the REAL production code paths -- they fail
 *    if the production serialization/parsing changes.
 *  - Tests that need the gomobile native bridge (mobile.Mobile) cannot run on the JVM.
 *    They SKIP LOUDLY via assumeTrue(isGoMobileAvailable()) instead of silently passing
 *    (JUnit reports them as ignored, not green). Their real coverage is the on-device
 *    OperationManagerIntegrationTest crypto roundtrip.
 */
class GoBridgeTest {

    /** True only when the gomobile AAR (mobile.Mobile) is loadable in this runtime. */
    private fun isGoMobileAvailable(): Boolean {
        return try {
            Class.forName("mobile.Mobile")
            true
        } catch (e: ClassNotFoundException) {
            false
        } catch (e: UnsatisfiedLinkError) {
            false
        } catch (e: NoClassDefFoundError) {
            false
        }
    }

    // --- Request JSON building: asserts the REAL production builders ------------------
    // These call GoBridge.build*RequestJson (the exact code startEncrypt/startDecrypt
    // send to Go), so they fail if a field is dropped, renamed, or retyped. No AAR needed.

    @Test
    fun `buildEncryptRequestJson serializes every option and never the password`() {
        val json = JSONObject(
            GoBridge.buildEncryptRequestJson(
                operationID = "test_op_123",
                inputFile = "/path/to/input.txt",
                outputFile = "/path/to/output.pcv",
                options = EncryptOptions(
                    comments = "Test comments",
                    paranoid = true,
                    reedSolomon = true,
                    deniability = false,
                    compress = true,
                    keyfiles = listOf("keyfile1", "keyfile2"),
                    keyfileOrdered = true
                )
            )
        )

        assertEquals("test_op_123", json.getString("operationID"))
        assertEquals("/path/to/input.txt", json.getString("inputFile"))
        assertEquals("/path/to/output.pcv", json.getString("outputFile"))
        assertEquals("Test comments", json.getString("comments"))
        assertTrue(json.getBoolean("paranoid"))
        assertTrue(json.getBoolean("reedSolomon"))
        assertFalse(json.getBoolean("deniability"))
        assertTrue(json.getBoolean("compress"))
        assertTrue(json.getBoolean("keyfileOrdered"))

        val keyfiles = json.getJSONArray("keyfiles")
        assertEquals(2, keyfiles.length())
        assertEquals("keyfile1", keyfiles.getString(0))
        assertEquals("keyfile2", keyfiles.getString(1))

        // SECURITY: the password is handed to Mobile as raw bytes, never serialized.
        assertFalse("password must never appear in the JSON", json.has("password"))
    }

    @Test
    fun `buildDecryptRequestJson serializes every option and never the password`() {
        val json = JSONObject(
            GoBridge.buildDecryptRequestJson(
                operationID = "test_op_123",
                inputFile = "/path/to/input.pcv",
                outputFile = "/path/to/output.txt",
                options = DecryptOptions(
                    keyfiles = listOf("keyfile1"),
                    forceDecrypt = true,
                    verifyFirst = true,
                    autoUnzip = false,
                    sameLevel = true,
                    recombine = false,
                    deniability = true
                )
            )
        )

        assertEquals("test_op_123", json.getString("operationID"))
        assertEquals("/path/to/input.pcv", json.getString("inputFile"))
        assertEquals("/path/to/output.txt", json.getString("outputFile"))
        assertTrue(json.getBoolean("forceDecrypt"))
        assertTrue(json.getBoolean("verifyFirst"))
        assertFalse(json.getBoolean("autoUnzip"))
        assertTrue(json.getBoolean("sameLevel"))
        assertFalse(json.getBoolean("recombine"))
        assertTrue(json.getBoolean("deniability"))

        val keyfiles = json.getJSONArray("keyfiles")
        assertEquals(1, keyfiles.length())
        assertEquals("keyfile1", keyfiles.getString(0))

        assertFalse("password must never appear in the JSON", json.has("password"))
    }

    // --- Response parsing: asserts the REAL production parser -------------------------

    @Test
    fun `parseDecryptionInfo maps every header field`() {
        val info = GoBridge.parseDecryptionInfo(
            """
            {
                "keyfilesRequired": true,
                "keyfileOrdered": true,
                "reedSolomon": true,
                "deniability": false,
                "paranoid": true,
                "comments": "Test comments",
                "readable": true
            }
            """.trimIndent()
        )

        assertTrue(info.keyfilesRequired)
        assertTrue(info.keyfileOrdered)
        assertTrue(info.reedSolomon)
        assertFalse(info.deniability)
        assertTrue(info.paranoid)
        assertEquals("Test comments", info.comments)
        assertTrue(info.readable)
    }

    @Test
    fun `parseDecryptionInfo throws on a missing required field`() {
        // SECURITY: a malformed header response must fail loud, not silently default
        // (e.g. defaulting keyfilesRequired=false would let the UI skip the keyfile
        // prompt). The production parser uses getBoolean, which throws on a missing key.
        val missingKeyfilesRequired = """
            {
                "keyfileOrdered": false,
                "reedSolomon": false,
                "deniability": false,
                "paranoid": false,
                "comments": "",
                "readable": true
            }
        """.trimIndent()

        assertThrows(JSONException::class.java) {
            GoBridge.parseDecryptionInfo(missingKeyfilesRequired)
        }
    }

    // --- Password zeroing: security contract that holds even when the call fails ------
    // GoBridge.start{Encrypt,Decrypt} zero the caller's password in a finally block. On
    // the JVM the native Mobile call throws, but finally still runs, so these verify the
    // wipe WITHOUT the AAR (and on-device, where Mobile returns, the finally still runs).

    @Test
    fun `startEncrypt zeroes the password even when the bridge call fails`() {
        val password = "hunter2".toByteArray(Charsets.UTF_8)
        try {
            GoBridge.startEncrypt("op_missing", "/no/such/in", "/tmp/out.pcv", password, EncryptOptions())
        } catch (t: Throwable) {
            // Native bridge unavailable on the JVM; the finally block has already run.
        }
        assertTrue("password bytes must be zeroed", password.all { it == 0.toByte() })
    }

    @Test
    fun `startDecrypt zeroes the password even when the bridge call fails`() {
        val password = "hunter2".toByteArray(Charsets.UTF_8)
        try {
            GoBridge.startDecrypt("op_missing", "/no/such/in.pcv", "/tmp/out", password, DecryptOptions())
        } catch (t: Throwable) {
            // Native bridge unavailable on the JVM; the finally block has already run.
        }
        assertTrue("password bytes must be zeroed", password.all { it == 0.toByte() })
    }

    // --- Option/struct defaults: guard against accidental default changes -------------

    @Test
    fun `EncryptOptions has correct defaults`() {
        val options = EncryptOptions()
        assertEquals("", options.comments)
        assertFalse(options.paranoid)
        assertFalse(options.reedSolomon)
        assertFalse(options.deniability)
        assertFalse(options.compress)
        assertEquals(emptyList<String>(), options.keyfiles)
        assertFalse(options.keyfileOrdered)
    }

    @Test
    fun `DecryptOptions has correct defaults`() {
        // autoUnzip MUST default false: Go auto-unzip orphans Android's single-file
        // export (see OperationManager). A regression here re-introduces SaveFailed.
        val options = DecryptOptions()
        assertEquals(emptyList<String>(), options.keyfiles)
        assertFalse(options.forceDecrypt)
        assertFalse(options.verifyFirst)
        assertFalse(options.autoUnzip)
        assertFalse(options.sameLevel)
        assertFalse(options.recombine)
        assertFalse(options.deniability)
    }

    @Test
    fun `ProgressState has correct defaults`() {
        val progressState = ProgressState(
            status = "Processing",
            progress = 0.5f,
            info = "Encrypting file...",
            done = false
        )
        assertEquals("Processing", progressState.status)
        assertEquals(0.5f, progressState.progress, 0.001f)
        assertEquals("Encrypting file...", progressState.info)
        assertFalse(progressState.done)
        assertEquals("code defaults to empty until an error is classified", "", progressState.code)
    }

    // --- Bridge-only contracts: skip loudly on the JVM (covered on-device) ------------

    @Test
    fun `startOperation returns a non-empty operation ID`() {
        assumeTrue("requires the gomobile AAR (mobile.Mobile)", isGoMobileAvailable())
        val result = GoBridge.startOperation()
        assertTrue("startOperation should succeed with the AAR present", result.isSuccess)
        result.onSuccess { assertTrue("operation ID must not be empty", it.isNotEmpty()) }
    }

    @Test
    fun `detectOperation wraps a binding failure as an AppError`() {
        assumeTrue("requires the gomobile AAR (mobile.Mobile)", isGoMobileAvailable())
        // Empty path -> Go reports an error -> bridge must wrap it as a typed AppError.
        val result = GoBridge.detectOperation("")
        result.onFailure {
            assertTrue("must be a GenericOperation AppError", it is AppError.OperationError.GenericOperation)
        }
    }
}
