package dev.keiji.deviceintegrity.ui.nav.contract

import android.content.Context
import android.content.Intent

interface LicenseNavigator {
    fun newIntent(context: Context): Intent
}
