package dev.keiji.deviceintegrity.ui.license

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.provider.contract.AssetInputStreamProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.InputStreamReader
import javax.inject.Inject

// LicenseInfo data class は LicenseScreen.kt から移動するか、
// 共通のdomainモジュールなどにあればそれを使うべきですが、
// 今回はここに再定義するか、そのまま LicenseScreen.kt のものを使う前提で進めます。
//ひとまず、LicenseScreen.ktにあるものを参照すると仮定します。

@HiltViewModel
class LicenseViewModel @Inject constructor(
    private val assetInputStreamProvider: AssetInputStreamProvider
) : ViewModel() {

    private val _licenseText = MutableStateFlow<String?>(null)
    val licenseText: StateFlow<String?> = _licenseText.asStateFlow()

    // TODO: 将来的には LicenseInfo のリストを保持するようにする
    // private val _licenses = MutableStateFlow<List<LicenseInfo>>(emptyList())
    // val licenses: StateFlow<List<LicenseInfo>> = _licenses.asStateFlow()

    init {
        loadLicenseFile()
    }

    private fun loadLicenseFile() {
        viewModelScope.launch {
            try {
                val inputStream = assetInputStreamProvider.openLicense()
                // TODO: 本来はここでJSONをパースして LicenseInfo のリストに変換する
                // 今回はInputStreamをテキストとして読み込み、保持するだけ
                val reader = InputStreamReader(inputStream)
                _licenseText.value = reader.readText()
                reader.close()
                inputStream.close()
                // Log.d("LicenseViewModel", "License Text: ${_licenseText.value}") // 必要ならログ出力
            } catch (e: Exception) {
                // Handle error, e.g., show an error message to the user
                _licenseText.value = "Error loading license file: ${e.message}"
                // Log.e("LicenseViewModel", "Error loading license", e) // 必要ならエラーログ出力
            }
        }
    }
}
