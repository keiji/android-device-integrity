package dev.keiji.deviceintegrity.ui.nav.contract

import android.content.Context
import android.content.Intent

interface AgreementNavigator {
    fun newIntent(context: Context): Intent
}
