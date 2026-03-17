package com.tgwsproxy

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

data class ProxyConfig(
    val port: Int = 1080,
    val host: String = "127.0.0.1",
    val dcIpList: List<String> = listOf("2:149.154.167.220", "4:149.154.167.220"),
    val verbose: Boolean = false,
    val autoStart: Boolean = false
)

object ConfigManager {

    private const val PREFS_NAME = "tgwsproxy_config"
    private const val KEY_PORT = "port"
    private const val KEY_HOST = "host"
    private const val KEY_DC_IP = "dc_ip"
    private const val KEY_VERBOSE = "verbose"
    private const val KEY_AUTO_START = "auto_start"

    fun load(context: Context): ProxyConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val dcIpJson = prefs.getString(KEY_DC_IP, null)
        val dcIpList = if (dcIpJson != null) {
            val arr = JSONArray(dcIpJson)
            (0 until arr.length()).map { arr.getString(it) }
        } else {
            listOf("2:149.154.167.220", "4:149.154.167.220")
        }
        return ProxyConfig(
            port = prefs.getInt(KEY_PORT, 1080),
            host = prefs.getString(KEY_HOST, "127.0.0.1") ?: "127.0.0.1",
            dcIpList = dcIpList,
            verbose = prefs.getBoolean(KEY_VERBOSE, false),
            autoStart = prefs.getBoolean(KEY_AUTO_START, false)
        )
    }

    fun save(context: Context, config: ProxyConfig) {
        val arr = JSONArray()
        config.dcIpList.forEach { arr.put(it) }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY_PORT, config.port)
            .putString(KEY_HOST, config.host)
            .putString(KEY_DC_IP, arr.toString())
            .putBoolean(KEY_VERBOSE, config.verbose)
            .putBoolean(KEY_AUTO_START, config.autoStart)
            .apply()
    }

    fun parseDcIpList(list: List<String>): Map<Int, String> {
        val result = mutableMapOf<Int, String>()
        for (entry in list) {
            val parts = entry.split(":", limit = 2)
            if (parts.size != 2) throw IllegalArgumentException("Неверный формат '$entry', нужно DC:IP")
            val dc = parts[0].toIntOrNull()
                ?: throw IllegalArgumentException("Неверный DC в '$entry'")
            result[dc] = parts[1].trim()
        }
        return result
    }
}
