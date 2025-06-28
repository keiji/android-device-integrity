package dev.keiji.deviceintegrity.ui.nav.contract

import android.content.Context
import android.content.Intent

interface AgreementNavigator {
    fun createAgreementIntent(context: Context): Intent
}
