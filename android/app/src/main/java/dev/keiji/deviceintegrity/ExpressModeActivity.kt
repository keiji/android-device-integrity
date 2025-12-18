package dev.keiji.deviceintegrity

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class ExpressModeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val textView = TextView(this)
        textView.text = "Express Mode (Not Implemented)"
        setContentView(textView)
    }
}
