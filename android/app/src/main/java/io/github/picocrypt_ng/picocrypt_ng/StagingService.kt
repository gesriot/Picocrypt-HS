package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

enum class SelectionKind { SINGLE_FILE, MULTI_FILE, FOLDER }

data class StagedSelection(
    val kind: SelectionKind,
    val displayName: String,
    val stagingRoot: String,
    val inputFiles: List<String>,
    val onlyFolders: List<String>,
    val onlyFiles: List<String>,
    val suggestedOutputName: String,
)

object StagingService {
    private const val STAGING_DIR = "picocrypt_files/staging"

    // ---- pure helpers (JVM-testable) ----
    fun resolveCollision(existing: Set<String>, name: String): String {
        if (name !in existing) return name
        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""
        var i = 1
        while ("$stem ($i)$ext" in existing) i++
        return "$stem ($i)$ext"
    }
    fun folderOutputName(rootName: String): String = "$rootName.zip.pcv"
    fun multiFileOutputName(unixSeconds: Long): String = "encrypted-$unixSeconds.zip.pcv"

    const val SPACE_MARGIN_BYTES: Long = 16L * 1024 * 1024 // 16 MiB headroom

    /** Peak internal usage ~= staged copy + encrypted temp zip + output volume, before cleanup. */
    fun requiredBytes(total: Long): Long = 3L * total + SPACE_MARGIN_BYTES
    fun hasSpaceFor(total: Long, usable: Long): Boolean = usable >= requiredBytes(total)

    private fun usableSpace(context: Context): Long =
        File(context.filesDir, STAGING_DIR).let { it.mkdirs(); it.usableSpace }

    private fun treeSize(dir: DocumentFile): Long {
        var sum = 0L
        for (c in dir.listFiles()) {
            if (c.isVirtual) continue
            sum += if (c.isDirectory) treeSize(c) else c.length()
        }
        return sum
    }

    private fun insufficient(total: Long, usable: Long) = AppError.FileError.InsufficientStorage(
        userMessage = "Not enough free space. This selection needs about " +
            "${requiredBytes(total) / (1024 * 1024)} MiB free; ${usable / (1024 * 1024)} MiB available.",
        technicalMessage = "required=${requiredBytes(total)} usable=$usable",
    )

    // ---- IO ----
    private fun stagingDir(context: Context): File = File(context.filesDir, STAGING_DIR).also { it.mkdirs() }
    fun wipeStaging(context: Context) { File(context.filesDir, STAGING_DIR).deleteRecursively() }

    suspend fun copyTreeToStaging(context: Context, treeUri: Uri): Result<StagedSelection> =
        withContext(Dispatchers.IO) {
            val tree = DocumentFile.fromTreeUri(context, treeUri)
                ?: return@withContext Result.failure(copyError("Could not open folder", "$treeUri"))
            stageTree(context, tree)
        }

    internal suspend fun stageTree(context: Context, tree: DocumentFile): Result<StagedSelection> =
        withContext(Dispatchers.IO) {
            try {
                wipeStaging(context)
                val total = treeSize(tree)
                val usable = usableSpace(context)
                if (!hasSpaceFor(total, usable)) return@withContext Result.failure(insufficient(total, usable))
                val rootName = tree.name ?: "folder"
                val root = File(stagingDir(context), rootName)
                val files = mutableListOf<String>()
                copyChildren(context, tree, root, files)
                if (files.isEmpty()) return@withContext Result.failure(copyError("The selected folder is empty", rootName))
                Result.success(
                    StagedSelection(
                        kind = SelectionKind.FOLDER,
                        displayName = rootName,
                        stagingRoot = stagingDir(context).absolutePath,
                        inputFiles = files,
                        onlyFolders = listOf(root.absolutePath),
                        onlyFiles = emptyList(),
                        suggestedOutputName = folderOutputName(rootName),
                    )
                )
            } catch (e: CancellationException) {
                wipeStaging(context); throw e
            } catch (e: Exception) {
                wipeStaging(context)
                Result.failure(copyError("Failed to read folder: ${e.message ?: "error"}", e.message))
            }
        }

    private fun copyChildren(context: Context, dir: DocumentFile, dest: File, out: MutableList<String>) {
        dest.mkdirs()
        for (child in dir.listFiles()) {
            if (child.isVirtual) continue
            val name = child.name ?: continue
            when {
                child.isDirectory -> copyChildren(context, child, File(dest, name), out)
                child.isFile -> {
                    val target = File(dest, name)
                    context.contentResolver.openInputStream(child.uri)?.use { input ->
                        FileOutputStream(target).use { output -> input.copyTo(output) }
                    } ?: throw IllegalStateException("could not open ${child.uri}")
                    out.add(target.absolutePath)
                }
            }
        }
    }

    suspend fun copyFilesToStaging(context: Context, uris: List<Uri>, nowUnixSeconds: Long): Result<StagedSelection> =
        withContext(Dispatchers.IO) {
            try {
                wipeStaging(context)
                val total = uris.sumOf { DocumentFile.fromSingleUri(context, it)?.length() ?: 0L }
                val usable = usableSpace(context)
                if (!hasSpaceFor(total, usable)) return@withContext Result.failure(insufficient(total, usable))
                val dir = stagingDir(context)
                val used = mutableSetOf<String>()
                val files = mutableListOf<String>()
                for (uri in uris) {
                    val display = queryDisplayName(context, uri) ?: "file"
                    val name = resolveCollision(used, display)
                    used.add(name)
                    val target = File(dir, name)
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(target).use { output -> input.copyTo(output) }
                    } ?: return@withContext Result.failure(copyError("Could not open a selected file", "$uri"))
                    files.add(target.absolutePath)
                }
                if (files.isEmpty()) return@withContext Result.failure(copyError("No files selected", null))
                Result.success(
                    StagedSelection(
                        kind = SelectionKind.MULTI_FILE,
                        displayName = if (files.size == 1) used.first() else "${files.size} files",
                        stagingRoot = dir.absolutePath,
                        inputFiles = files,
                        onlyFolders = emptyList(),
                        onlyFiles = files,
                        suggestedOutputName = multiFileOutputName(nowUnixSeconds),
                    )
                )
            } catch (e: CancellationException) {
                wipeStaging(context); throw e
            } catch (e: Exception) {
                wipeStaging(context)
                Result.failure(copyError("Failed to copy files: ${e.message ?: "error"}", e.message))
            }
        }

    private fun queryDisplayName(context: Context, uri: Uri): String? {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (i != -1) return c.getString(i)
            }
        }
        return null
    }

    private fun copyError(user: String, tech: String?) =
        AppError.FileError.CopyFailed(userMessage = user, technicalMessage = tech)
}
