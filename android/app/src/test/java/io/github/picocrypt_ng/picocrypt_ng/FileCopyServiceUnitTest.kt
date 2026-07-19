package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import java.io.File
import kotlin.io.path.createTempDirectory
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FileCopyServiceUnitTest {
    @Test
    fun cleanupAllFiles_reportsFailureWhenInternalDirectoryCannotBeListed() = runTest {
        val filesDir = createTempDirectory("picocrypt-files-dir").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        assertTrue("Internal directory should be created for test setup", internalDir.mkdirs())

        try {
            assertTrue(
                "Test setup should remove read permission from the internal directory",
                internalDir.setReadable(false, false),
            )
            assertTrue(
                "Test setup should remove execute permission from the internal directory",
                internalDir.setExecutable(false, false),
            )

            val result = FileCopyService.cleanupAllFiles(context)

            assertFalse("Cleanup must fail loud when existing staged files cannot be listed", result)
        } finally {
            internalDir.setReadable(true, false)
            internalDir.setExecutable(true, false)
            filesDir.deleteRecursively()
        }
    }
}
