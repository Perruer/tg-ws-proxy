package com.tgwsproxy.proxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.tgwsproxy.ConfigManager
import com.tgwsproxy.proxy.ProxyService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val config = ConfigManager.load(context)
            if (config.autoStart) {
                ProxyService.start(context)
            }
        }
    }
}