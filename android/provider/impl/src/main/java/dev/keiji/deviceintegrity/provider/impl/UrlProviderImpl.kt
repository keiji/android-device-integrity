package dev.keiji.deviceintegrity.provider.impl

import android.content.Context
import androidx.annotation.StringRes
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.keiji.deviceintegrity.provider.contract.UrlProvider
import javax.inject.Inject

class UrlProviderImpl @Inject constructor(
    @param:ApplicationContext private val context: Context,
    @param:StringRes private val termsOfServiceUrlResId: Int,
    @param:StringRes private val privacyPolicyUrlResId: Int,
    @param:StringRes private val aboutAppUrlResId: Int,
) : UrlProvider {

    override val termsOfServiceUrl: String
        get() = context.getString(termsOfServiceUrlResId)

    override val privacyPolicyUrl: String
        get() = context.getString(privacyPolicyUrlResId)

    override val aboutAppUrl: String
        get() = context.getString(aboutAppUrlResId)
}
