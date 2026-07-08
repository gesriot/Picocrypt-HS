package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class AndroidStringResourcesTest {
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
    fun `task three error strings exist with positional placeholders`() {
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

    private fun assertPlural(name: String, one: String, other: String) {
        val element = pluralElement(name)
        val quantities = mutableMapOf<String, String>()
        val items = element.getElementsByTagName("item")
        for (index in 0 until items.length) {
            val item = items.item(index) as Element
            quantities[item.getAttribute("quantity")] = item.textContent
        }

        assertEquals(one, quantities["one"])
        assertEquals(other, quantities["other"])
        assertTrue("Plural $name should only define one and other", quantities.keys == setOf("one", "other"))
    }
}
