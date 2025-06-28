package dev.keiji.deviceintegrity.ui.nav.contract

import android.content.Intent
import androidx.activity.result.ActivityResultLauncher

interface AgreementNavigator {
    fun interface ResultCallback {
        fun onResult(isAgreed: Boolean)
    }

    fun navigateToAgreement(
        activityResultLauncher: ActivityResultLauncher<Intent>,
    )
}
