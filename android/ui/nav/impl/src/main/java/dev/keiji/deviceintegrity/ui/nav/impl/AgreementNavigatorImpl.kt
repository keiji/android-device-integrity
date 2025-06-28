package dev.keiji.deviceintegrity.ui.nav.impl

import android.content.Context
import android.content.Intent
import androidx.activity.result.ActivityResultLauncher
import dev.keiji.deviceintegrity.ui.agreement.AgreementActivity
import dev.keiji.deviceintegrity.ui.nav.contract.AgreementNavigator

class AgreementNavigatorImpl(
    private val context: Context
) : AgreementNavigator {

    override fun navigateToAgreement(
        activityResultLauncher: ActivityResultLauncher<Intent>,
    ) {
        val intent = Intent(context, AgreementActivity::class.java)
        activityResultLauncher.launch(intent)
    }
}
