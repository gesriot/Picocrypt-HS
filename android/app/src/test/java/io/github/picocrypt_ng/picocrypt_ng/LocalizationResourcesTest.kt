package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class LocalizationResourcesTest {
    private val stringsFile = File("src/main/res/values/strings.xml")
    private val document by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(stringsFile)
    }

    @Test
    fun `app name stays non translatable`() {
        val appName = stringElement("app_name")

        assertEquals("false", appName.getAttribute("translatable"))
        assertEquals("Picocrypt-NG", appName.textContent)
    }

    @Test
    fun `every plural resource defines an other quantity`() {
        val missingOther = pluralElements()
            .filter { element -> pluralItems(element).none { it.first == "other" } }
            .map { it.getAttribute("name") }

        assertTrue("Plural resources missing quantity=\"other\": $missingOther", missingOther.isEmpty())
    }

    @Test
    fun `base catalog does not use file parenthetical shortcuts`() {
        val offenders = textResources()
            .filter { it.text.contains("file(s)", ignoreCase = true) }
            .map { "${it.name}: ${it.text}" }

        assertTrue("Use real plural resources instead of file(s): $offenders", offenders.isEmpty())
    }

    @Test
    fun `formatted strings use positional placeholders`() {
        val offenders = textResources().flatMap { resource ->
            formatSpecifiers.findAll(resource.text)
                .filter { it.groups[1] == null }
                .map { "${resource.name}: ${resource.text}" }
        }.distinct()

        assertTrue("Formatted resources must use positional placeholders: $offenders", offenders.isEmpty())
    }

    @Test
    fun `task three error strings stay in the base catalog`() {
        val expected = mapOf(
            "error_no_active_operation" to "No active operation.",
            "error_no_operation_to_retry" to "No active operation to retry.",
            "error_operation_data_unavailable" to "Operation data is not available for retry.",
            "error_decrypt_retry_only" to "Only decryption operations can be retried with force decrypt.",
            "error_could_not_open_folder" to "Could not open folder.",
            "error_selected_folder_empty" to "The selected folder is empty.",
            "error_read_folder_failed" to "Failed to read folder: %1\$s",
            "error_could_not_open_selected_file" to "Could not open a selected file.",
            "error_no_files_selected" to "No files selected.",
            "error_copy_files_failed" to "Failed to copy files: %1\$s",
            "error_detect_operation_type_failed" to "Failed to detect operation type.",
        )

        expected.forEach { (name, value) ->
            assertEquals(value, stringElement(name).textContent)
        }
    }

    @Test
    fun `technical filename extensions stay format arguments`() {
        assertEquals(
            "Split volumes are not supported on Android. Recombine the chunks on your computer first, then transfer the single %1\$s file.",
            stringElement("error_split_volume_not_supported").textContent,
        )

        val rawExtensionMentions = textResources()
            .filter { it.name != "app_name" }
            .filter { resource ->
                rawFilenameExtension.containsMatchIn(resource.text)
            }
            .map { "${it.name}: ${it.text}" }

        assertTrue(
            "Translator-facing strings must pass technical filename extensions as arguments: $rawExtensionMentions",
            rawExtensionMentions.isEmpty(),
        )
    }

    @Test
    fun `counted keyfile and selected file labels are plural resources`() {
        assertPlural(
            name = "keyfiles_count",
            one = "%1\$d keyfile",
            other = "%1\$d keyfiles",
        )
        assertPlural(
            name = "keyfiles_required_count",
            one = "%1\$d keyfile required",
            other = "%1\$d keyfiles required",
        )
        assertPlural(
            name = "selected_files_count",
            one = "%1\$d file selected",
            other = "%1\$d files selected",
        )
    }

    @Test
    fun `high risk wording keeps security meaning`() {
        assertContainsWords("force_decrypt_warning", "unverified", "corrupted")
        assertContainsWords("error_data_corrupted", "unverified", "corrupted")
        assertContainsWords("comments_plaintext_warning", "plaintext metadata")

        val deniabilityCopy = textResources()
            .filter { it.name.contains("deniability") }
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse("Deniability copy must not promise anonymity", deniabilityCopy.contains("anonymous"))
        assertFalse("Deniability copy must not call deniability a hidden mode", deniabilityCopy.contains("hidden mode"))

        val authenticationCopy = textResources()
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse(
            "Authentication copy must not imply Picocrypt-NG has accounts, logins, or authorization",
            disallowedAuthenticationWords.containsMatchIn(authenticationCopy),
        )
    }

    @Test
    fun `authentication wording guard rejects account login and authorization terms`() {
        val blockedTerms = listOf(
            "account",
            "login",
            "log in",
            "sign in",
            "signin",
            "authorization",
            "authorize",
            "authorized",
        )

        val missedTerms = blockedTerms.filterNot { term ->
            disallowedAuthenticationWords.containsMatchIn("Volume $term failed")
        }

        assertTrue("Authentication wording guard missed: $missedTerms", missedTerms.isEmpty())
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
        return pluralElements().firstOrNull { it.getAttribute("name") == name }
            ?: throw AssertionError("Missing plurals resource: $name")
    }

    private fun pluralElements(): List<Element> {
        val nodes = document.getElementsByTagName("plurals")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun pluralItems(element: Element): List<Pair<String, String>> {
        val items = element.getElementsByTagName("item")
        return List(items.length) { index ->
            val item = items.item(index) as Element
            item.getAttribute("quantity") to item.textContent
        }
    }

    private fun textResources(): List<TextResource> {
        val strings = document.getElementsByTagName("string")
        val stringResources = List(strings.length) { index ->
            val element = strings.item(index) as Element
            TextResource(element.getAttribute("name"), element.textContent)
        }
        val pluralResources = pluralElements().flatMap { plural ->
            val pluralName = plural.getAttribute("name")
            pluralItems(plural).map { (quantity, value) ->
                TextResource("$pluralName[$quantity]", value)
            }
        }
        return stringResources + pluralResources
    }

    private fun assertPlural(name: String, one: String, other: String) {
        val quantities = pluralItems(pluralElement(name)).toMap()

        assertEquals(one, quantities["one"])
        assertEquals(other, quantities["other"])
        assertTrue("Plural $name should only define one and other", quantities.keys == setOf("one", "other"))
    }

    private fun assertContainsWords(name: String, vararg words: String) {
        val text = stringElement(name).textContent.lowercase()
        words.forEach { word ->
            assertTrue("$name must contain \"$word\": $text", text.contains(word))
        }
    }

    private data class TextResource(val name: String, val text: String)

    private companion object {
        private val formatSpecifiers =
            Regex("""%(?!%)(?!n)(\d+\$)?[-#+ 0,(<]*\d*(?:\.\d+)?[a-zA-Z]""")
        private val disallowedAuthenticationWords =
            Regex("""\b(account|login|log in|sign in|signin|authorization|authorize|authorized)\b""")
        private val rawFilenameExtension =
            Regex("""\.(pcv|zip|bin|incomplete)\b""", RegexOption.IGNORE_CASE)
    }
}
