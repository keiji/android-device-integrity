package dev.keiji.deviceintegrity.ui.nav.impl

import android.content.Context
import android.content.Intent
import dev.keiji.deviceintegrity.ui.agreement.AgreementActivity
import dev.keiji.deviceintegrity.ui.nav.contract.AgreementNavigator
import javax.inject.Inject

class AgreementNavigatorImpl @Inject constructor() : AgreementNavigator {

    override fun createAgreementIntent(context: Context): Intent {
        return Intent(context, AgreementActivity::class.java)
    }
}
