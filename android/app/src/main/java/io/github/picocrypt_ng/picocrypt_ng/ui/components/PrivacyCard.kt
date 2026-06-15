package io.github.picocrypt_ng.picocrypt_ng.ui.components


import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.R


/**
 * Always-visible card exposing the screenshot-protection toggle. Pure composable: it
 * receives its state and reports changes, mirroring the inject-the-dependency convention
 * used by the other cards.
 */
@Composable
fun PrivacyCard(
    enabled: Boolean,
    onChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.privacy_security),
                style = MaterialTheme.typography.titleSmall
            )
            LabeledCheckbox(stringResource(R.string.prevent_screenshots), enabled, onChange)
            Text(
                text = stringResource(R.string.prevent_screenshots_description),
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
