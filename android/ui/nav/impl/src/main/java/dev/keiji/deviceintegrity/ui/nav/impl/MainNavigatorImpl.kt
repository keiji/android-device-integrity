package dev.keiji.deviceintegrity.ui.nav.impl

import android.content.Context
import android.content.Intent
import dev.keiji.deviceintegrity.ui.main.MainActivity
import dev.keiji.deviceintegrity.ui.nav.contract.MainNavigator
import javax.inject.Inject

class MainNavigatorImpl @Inject constructor() : MainNavigator {
    override fun newIntent(context: Context): Intent {
        return Intent(context, MainActivity::class.java)
    }
}
