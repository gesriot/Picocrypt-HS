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
    private val russianStringsFile = File("src/main/res/values-ru/strings.xml")
    private val document by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(stringsFile)
    }
    private val russianDocument by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(russianStringsFile)
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
    fun `folder and file copy failures preserve their reason placeholder`() {
        listOf("error_read_folder_failed", "error_copy_files_failed").forEach { name ->
            assertEquals(listOf("%1\$s"), formatSpecifiersIn(stringElement(name).textContent))
        }
    }

    @Test
    fun `russian catalog mirrors base translatable resources`() {
        assertTrue("Missing Russian resources at ${russianStringsFile.path}", russianStringsFile.isFile)

        val baseStringNames = stringElements(document)
            .filterNot { it.getAttribute("translatable") == "false" }
            .map { it.getAttribute("name") }
        val russianStringNames = stringElements(russianDocument)
            .map { it.getAttribute("name") }

        assertEquals(baseStringNames, russianStringNames)
        assertEquals(pluralNames(document), pluralNames(russianDocument))
    }

    @Test
    fun `russian plurals use Russian quantity categories`() {
        pluralNames(document).forEach { name ->
            val quantities = pluralItems(pluralElement(russianDocument, name))
                .map { it.first }
                .toSet()

            assertEquals(
                "Russian plural $name should define one, few, many, and other",
                setOf("one", "few", "many", "other"),
                quantities,
            )
        }
    }

    @Test
    fun `russian formatted resources preserve base placeholders`() {
        val baseStrings = stringElements(document)
            .associate { it.getAttribute("name") to formatSpecifiersIn(it.textContent) }
        val stringMismatches = stringElements(russianDocument)
            .filter { russian -> formatSpecifiersIn(russian.textContent) != baseStrings[russian.getAttribute("name")] }
            .map { russian ->
                val name = russian.getAttribute("name")
                "$name: ${formatSpecifiersIn(russian.textContent)} != ${baseStrings[name]}"
            }

        val basePluralOther = pluralElements(document)
            .associate { plural ->
                val name = plural.getAttribute("name")
                val other = pluralItems(plural).first { it.first == "other" }.second
                name to formatSpecifiersIn(other)
            }
        val pluralMismatches = pluralElements(russianDocument).flatMap { plural ->
            val name = plural.getAttribute("name")
            val expected = basePluralOther[name]
            pluralItems(plural)
                .filter { (_, text) -> formatSpecifiersIn(text) != expected }
                .map { (quantity, text) -> "$name[$quantity]: ${formatSpecifiersIn(text)} != $expected" }
        }

        val placeholderMismatches = stringMismatches + pluralMismatches

        assertTrue(
            "Russian resources must preserve positional format placeholders: $placeholderMismatches",
            placeholderMismatches.isEmpty(),
        )
    }

    @Test
    fun `russian high risk wording keeps security meaning`() {
        assertRussianContains("force_decrypt_warning", "непровер", "повреж")
        assertRussianContains("error_data_corrupted", "не провер", "повреж")
        assertRussianContains("error_decrypt_retry_only", "только", "расшифр", "принуд")
        assertRussianContains("comments_plaintext_warning", "открыт", "метадан")
        assertRussianContains("error_auth_failed", "парол", "ключев")

        val deniabilityCopy = textResources(russianDocument)
            .filter { it.name.contains("deniability") }
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse("Russian deniability copy must not promise anonymity", deniabilityCopy.contains("аноним"))
        assertFalse("Russian deniability copy must not promise invisibility", deniabilityCopy.contains("невидим"))
        assertFalse("Russian deniability copy must not call deniability a hidden mode", deniabilityCopy.contains("скрытый режим"))

        val authenticationCopy = textResources(russianDocument)
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse(
            "Russian authentication copy must not imply accounts, logins, or authorization",
            disallowedRussianAuthenticationWords.containsMatchIn(authenticationCopy),
        )
    }

    @Test
    fun `technical filename extensions stay format arguments`() {
        assertContainsWords("error_split_volume_not_supported", "not supported", "recombine")
        assertRussianContains("error_split_volume_not_supported", "не поддерж", "объедин")
        assertEquals(
            listOf("%1\$s"),
            formatSpecifiersIn(stringElement("error_split_volume_not_supported").textContent),
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
    fun `insufficient storage message keeps required and available byte placeholders`() {
        assertEquals(
            listOf("%1\$d", "%2\$d"),
            formatSpecifiersIn(stringElement("error_insufficient_storage").textContent),
        )
    }

    @Test
    fun `counted keyfile and selected file labels are plural resources`() {
        assertPlural("keyfiles_count")
        assertPlural("keyfiles_required_count")
        assertPlural("selected_files_count")
    }

    @Test
    fun `high risk wording keeps security meaning`() {
        assertContainsWords("force_decrypt_warning", "unverified", "corrupted")
        assertContainsWords("error_data_corrupted", "unverified", "corrupted")
        assertContainsWords("error_decrypt_retry_only", "only", "decryption", "force decrypt")
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
        return stringElement(document, name)
    }

    private fun stringElement(document: org.w3c.dom.Document, name: String): Element {
        val nodes = document.getElementsByTagName("string")
        for (index in 0 until nodes.length) {
            val element = nodes.item(index) as Element
            if (element.getAttribute("name") == name) return element
        }
        throw AssertionError("Missing string resource: $name")
    }

    private fun pluralElement(name: String): Element {
        return pluralElement(document, name)
    }

    private fun pluralElement(document: org.w3c.dom.Document, name: String): Element {
        return pluralElements(document).firstOrNull { it.getAttribute("name") == name }
            ?: throw AssertionError("Missing plurals resource: $name")
    }

    private fun pluralElements(document: org.w3c.dom.Document = this.document): List<Element> {
        val nodes = document.getElementsByTagName("plurals")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun pluralNames(document: org.w3c.dom.Document): List<String> {
        return pluralElements(document).map { it.getAttribute("name") }
    }

    private fun pluralItems(element: Element): List<Pair<String, String>> {
        val items = element.getElementsByTagName("item")
        return List(items.length) { index ->
            val item = items.item(index) as Element
            item.getAttribute("quantity") to item.textContent
        }
    }

    private fun textResources(): List<TextResource> {
        return textResources(document)
    }

    private fun textResources(document: org.w3c.dom.Document): List<TextResource> {
        val strings = document.getElementsByTagName("string")
        val stringResources = List(strings.length) { index ->
            val element = strings.item(index) as Element
            TextResource(element.getAttribute("name"), element.textContent)
        }
        val pluralResources = pluralElements(document).flatMap { plural ->
            val pluralName = plural.getAttribute("name")
            pluralItems(plural).map { (quantity, value) ->
                TextResource("$pluralName[$quantity]", value)
            }
        }
        return stringResources + pluralResources
    }

    private fun assertPlural(name: String) {
        val items = pluralItems(pluralElement(name))

        assertEquals(
            "Plural $name should define one and other exactly once",
            listOf("one", "other"),
            items.map { it.first }.sorted(),
        )
        items.forEach { (quantity, text) ->
            assertEquals(
                "Plural $name[$quantity] should format its count exactly once",
                listOf("%1\$d"),
                formatSpecifiersIn(text),
            )
        }
    }

    private fun assertContainsWords(name: String, vararg words: String) {
        val text = stringElement(name).textContent.lowercase()
        words.forEach { word ->
            assertTrue("$name must contain \"$word\": $text", text.contains(word))
        }
    }

    private fun assertRussianContains(name: String, vararg fragments: String) {
        val text = stringElement(russianDocument, name).textContent.lowercase()
        fragments.forEach { fragment ->
            assertTrue("$name must contain Russian fragment \"$fragment\": $text", text.contains(fragment))
        }
    }

    private fun stringElements(document: org.w3c.dom.Document): List<Element> {
        val nodes = document.getElementsByTagName("string")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun formatSpecifiersIn(text: String): List<String> {
        return formatSpecifiers.findAll(text).map { match -> match.value }.toList().sorted()
    }

    private data class TextResource(val name: String, val text: String)

    private companion object {
        private val formatSpecifiers =
            Regex("""%(?!%)(?!n)(\d+\$)?[-#+ 0,(<]*\d*(?:\.\d+)?[a-zA-Z]""")
        private val disallowedAuthenticationWords =
            Regex("""\b(account|login|log in|sign in|signin|authorization|authorize|authorized)\b""")
        private val disallowedRussianAuthenticationWords =
            Regex("""\b(аккаунт|уч[её]тн\w*|логин|вход|авторизац\w*)\b""")
        private val rawFilenameExtension =
            Regex("""\.(pcv|zip|bin|incomplete)\b""", RegexOption.IGNORE_CASE)
    }
}
