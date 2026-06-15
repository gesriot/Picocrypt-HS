package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.assertEquals
import org.junit.Test

class StagingServiceTest {
    @Test fun resolveCollision_uniqueWhenFree() {
        assertEquals("a.txt", StagingService.resolveCollision(emptySet(), "a.txt"))
    }
    @Test fun resolveCollision_appendsCounter() {
        assertEquals("a (1).txt", StagingService.resolveCollision(setOf("a.txt"), "a.txt"))
        assertEquals("a (2).txt", StagingService.resolveCollision(setOf("a.txt", "a (1).txt"), "a.txt"))
    }
    @Test fun resolveCollision_noExtension() {
        assertEquals("README (1)", StagingService.resolveCollision(setOf("README"), "README"))
    }
    @Test fun multiFileOutputName_isRandomEncryptedZipPcv() {
        assertEquals("encrypted-1700000000.zip.pcv", StagingService.multiFileOutputName(1_700_000_000L))
    }
    @Test fun folderOutputName_keepsRootName() {
        assertEquals("MyDocs.zip.pcv", StagingService.folderOutputName("MyDocs"))
    }
    @Test fun requiredBytes_isThreeXPlusMargin() {
        assertEquals(3L * 1000 + StagingService.SPACE_MARGIN_BYTES, StagingService.requiredBytes(1000))
    }
    @Test fun hasSpaceFor_refusesWhenTight() {
        assertEquals(false, StagingService.hasSpaceFor(total = 1000, usable = 3000))
        assertEquals(true, StagingService.hasSpaceFor(total = 1000, usable = 3L * 1000 + StagingService.SPACE_MARGIN_BYTES))
    }
}
