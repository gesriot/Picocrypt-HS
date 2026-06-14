package io.github.picocrypt_ng.picocrypt_ng

import androidx.documentfile.provider.DocumentFile
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class StagingServiceInstrumentedTest {
    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test fun stageTree_preservesStructure() = runBlocking {
        val src = File(ctx.cacheDir, "srctree").apply { deleteRecursively(); mkdirs() }
        File(src, "sub").mkdirs()
        File(src, "a.txt").writeText("a")
        File(src, "sub/b.txt").writeText("b")

        val tree = DocumentFile.fromFile(src)
        val sel = StagingService.stageTree(ctx, tree).getOrThrow()
        assertEquals(SelectionKind.FOLDER, sel.kind)
        assertEquals("srctree.zip.pcv", sel.suggestedOutputName)
        assertEquals(2, sel.inputFiles.size)
        assertTrue(sel.inputFiles.any { it.endsWith("/srctree/a.txt") })
        assertTrue(sel.inputFiles.any { it.endsWith("/srctree/sub/b.txt") })
        assertEquals(1, sel.onlyFolders.size)
        assertTrue(sel.onlyFolders[0].endsWith("/staging/srctree"))
        StagingService.wipeStaging(ctx)
    }
}
