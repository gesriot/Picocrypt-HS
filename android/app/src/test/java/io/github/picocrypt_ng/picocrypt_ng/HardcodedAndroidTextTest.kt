package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class HardcodedAndroidTextTest {
    private val javaRoot = File("src/main/java")
    private val stringsFile = File("src/main/res/values/strings.xml")
    private val document by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(stringsFile)
    }

    @Test
    fun `main source does not hardcode moved Android resource text`() {
        val blockedMessages = movedResourceTexts()
            .mapValues { (_, text) -> canonicalText(text) }
        val findings = sourceStringLiterals()
            .filterNot(::isAllowedTechnicalLiteral)
            .flatMap { literal ->
                blockedMessages.filterValues { blocked -> blocked == canonicalText(literal.value) }
                    .map { (resourceName, _) -> "${literal.location}: duplicates $resourceName (${literal.value})" }
            }

        assertTrue(
            "Move user-facing Android text to strings.xml instead of hardcoding it:\n" +
                findings.joinToString(separator = "\n"),
            findings.isEmpty(),
        )
    }

    private fun movedResourceTexts(): Map<String, String> {
        val resources = linkedMapOf<String, String>()
        movedStringResourceNames.forEach { name ->
            resources[name] = stringElement(name).textContent
        }
        movedPluralResourceNames.forEach { name ->
            pluralItems(pluralElement(name)).forEach { (quantity, text) ->
                resources["$name[$quantity]"] = text
            }
        }
        return resources
    }

    private fun sourceStringLiterals(): List<SourceLiteral> {
        return javaRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .flatMap { file -> stringLiteralsIn(file) }
            .toList()
    }

    private fun stringLiteralsIn(file: File): List<SourceLiteral> {
        val text = file.readText()
        return stringLiteral.findAll(text).map { match ->
            val value = match.groups[1]?.value ?: match.groups[2]?.value.orEmpty()
            val line = text.substring(0, match.range.first).count { it == '\n' } + 1
            val lineText = text.lineSequence().drop(line - 1).firstOrNull().orEmpty()
            SourceLiteral(file, line, value, lineText)
        }.toList()
    }

    private fun isAllowedTechnicalLiteral(literal: SourceLiteral): Boolean {
        val value = literal.value
        return value.isBlank() ||
            value.startsWith("io.github.") ||
            mimeType.matches(value) ||
            fileExtension.matches(value) ||
            generatedFileName.matches(value) ||
            value in jsonFieldNames ||
            value in stableGoErrorCodes ||
            (literal.file.name == "OperationStatus.kt" && value in operationStatusConstants) ||
            literal.lineText.contains("Log.") ||
            literal.lineText.contains("TAG")
    }

    private fun stringElement(name: String): Element {
        val nodes = document.getElementsByTagName("string")
        for (index in 0 until nodes.length) {
            val element = nodes.item(index) as Element
            if (element.getAttribute("name") == name) return element
        }
        throw AssertionError("Missing string resource: $name")
    }

    private fun pluralElement(name: String): Element {
        val nodes = document.getElementsByTagName("plurals")
        for (index in 0 until nodes.length) {
            val element = nodes.item(index) as Element
            if (element.getAttribute("name") == name) return element
        }
        throw AssertionError("Missing plurals resource: $name")
    }

    private fun pluralItems(element: Element): List<Pair<String, String>> {
        val items = element.getElementsByTagName("item")
        return List(items.length) { index ->
            val item = items.item(index) as Element
            item.getAttribute("quantity") to item.textContent
        }
    }

    private fun canonicalText(value: String): String {
        return value
            .lowercase()
            .trim()
            .trimEnd('.')
            .replace(Regex("""\s+"""), " ")
    }

    private data class SourceLiteral(
        val file: File,
        val line: Int,
        val value: String,
        val lineText: String,
    ) {
        val location: String = "${file.path}:$line"
    }

    private companion object {
        private val stringLiteral = Regex("\"\"\"([\\s\\S]*?)\"\"\"|\"((?:\\\\.|[^\"\\\\])*)\"")
        private val mimeType = Regex("""^[a-z]+/[a-z0-9.+-]+$""")
        private val fileExtension = Regex("""^\.[A-Za-z0-9]+$""")
        private val generatedFileName = Regex("""^[A-Za-z0-9_./ -]+\.(pcv|zip|bin|incomplete)$""")

        private val movedStringResourceNames = setOf(
            "error_no_active_operation",
            "error_no_operation_to_retry",
            "error_operation_data_unavailable",
            "error_decrypt_retry_only",
            "error_could_not_open_folder",
            "error_selected_folder_empty",
            "error_read_folder_failed",
            "error_could_not_open_selected_file",
            "error_no_files_selected",
            "error_copy_files_failed",
            "error_detect_operation_type_failed",
        )

        private val movedPluralResourceNames = setOf(
            "keyfiles_count",
            "keyfiles_required_count",
            "selected_files_count",
        )

        private val jsonFieldNames = setOf(
            "operationID",
            "inputFile",
            "inputFiles",
            "onlyFolders",
            "onlyFiles",
            "outputFile",
            "comments",
            "keyfiles",
            "paranoid",
            "reedSolomon",
            "deniability",
            "compress",
            "keyfileOrdered",
            "forceDecrypt",
            "verifyFirst",
            "autoUnzip",
            "sameLevel",
            "recombine",
            "keyfilesRequired",
            "readable",
        )

        private val stableGoErrorCodes = setOf(
            "AUTH_FAILED",
            "DATA_CORRUPTED",
            "FILE_NOT_FOUND",
            "CORRUPT_HEADER",
            "CANCELLED",
            "GENERIC",
        )

        private val operationStatusConstants = setOf(
            "Starting...",
            "Completed",
            "Cancelled",
            "Error",
        )
    }
}
