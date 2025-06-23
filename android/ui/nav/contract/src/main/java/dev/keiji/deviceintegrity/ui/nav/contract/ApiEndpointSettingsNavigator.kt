package dev.keiji.deviceintegrity.ui.nav.contract

import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContract

interface ApiEndpointSettingsNavigator {
    fun newIntent(context: Context): Intent

    fun contract(): ActivityResultContract<Unit, Unit>
}
