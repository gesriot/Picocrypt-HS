package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R

/**
 * Decrypt-only options card. Mirrors AdvancedCard (encrypt) but for decrypt-time
 * options. Currently exposes verify-first (integrity-verify-before-write); reuses the
 * ExpandableCard / LabeledCheckbox helpers defined in AdvancedCard.kt.
 */
@Composable
fun DecryptOptionsCard(viewModel: MainViewModel, modifier: Modifier = Modifier) {
    val formData by viewModel.formState.collectAsState()
    if (!formData.isDecrypt) {
        return
    }
    val count = (if (formData.verifyFirst) 1 else 0)
    ExpandableCard(title = stringResource(R.string.decrypt_options, count), modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp)) {
            LabeledCheckbox(stringResource(R.string.verify_first), formData.verifyFirst) {
                viewModel.updateFormData(formData.copy(verifyFirst = it))
            }
        }
    }
}
