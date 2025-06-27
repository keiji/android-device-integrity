package jp.co.android.provider.impl

import android.content.Context
import androidx.annotation.StringRes
import dagger.hilt.android.qualifiers.ApplicationContext
import jp.co.android.provider.contract.UrlProvider
import javax.inject.Inject

class UrlProviderImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    @StringRes private val termsOfServiceUrlResId: Int,
    @StringRes private val privacyPolicyUrlResId: Int,
    @StringRes private val aboutAppUrlResId: Int,
) : UrlProvider {

    override val termsOfServiceUrl: String
        get() = context.getString(termsOfServiceUrlResId)

    override val privacyPolicyUrl: String
        get() = context.getString(privacyPolicyUrlResId)

    override val aboutAppUrl: String
        get() = context.getString(aboutAppUrlResId)
}
