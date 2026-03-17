package com.tgwsproxy.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.switchmaterial.SwitchMaterial
import com.tgwsproxy.ConfigManager
import com.tgwsproxy.ProxyConfig
import com.tgwsproxy.R
import com.tgwsproxy.proxy.ProxyService
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var statusIndicator: View
    private lateinit var tvStatus: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var tvStats: TextView
    private lateinit var btnToggle: Button
    private lateinit var btnOpenTelegram: Button
    private lateinit var btnSaveConfig: Button
    private lateinit var editPort: EditText
    private lateinit var editHost: EditText
    private lateinit var editDcIp: EditText
    private lateinit var switchVerbose: SwitchMaterial
    private lateinit var switchAutoStart: SwitchMaterial

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusIndicator = findViewById(R.id.statusIndicator)
        tvStatus        = findViewById(R.id.tvStatus)
        tvStatusDetail  = findViewById(R.id.tvStatusDetail)
        tvStats         = findViewById(R.id.tvStats)
        btnToggle       = findViewById(R.id.btnToggle)
        btnOpenTelegram = findViewById(R.id.btnOpenTelegram)
        btnSaveConfig   = findViewById(R.id.btnSaveConfig)
        editPort        = findViewById(R.id.editPort)
        editHost        = findViewById(R.id.editHost)
        editDcIp        = findViewById(R.id.editDcIp)
        switchVerbose   = findViewById(R.id.switchVerbose)
        switchAutoStart = findViewById(R.id.switchAutoStart)

        requestNotificationPermission()
        requestBatteryOptimizationExemption()
        loadConfigToUI()
        updateStatus()

        btnToggle.setOnClickListener { toggleProxy() }
        btnOpenTelegram.setOnClickListener { openInTelegram() }
        btnSaveConfig.setOnClickListener { saveConfig() }

        lifecycleScope.launch {
            while (isActive) {
                delay(1_000)
                updateStatus()
            }
        }
    }

    private fun requestBatteryOptimizationExemption() {
        val pm = getSystemService(POWER_SERVICE) as android.os.PowerManager
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            try {
                startActivity(
                    android.content.Intent(
                        android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        android.net.Uri.parse("package:$packageName")
                    )
                )
            } catch (_: Exception) {}
        }
    }

    private fun loadConfigToUI() {
        val cfg = ConfigManager.load(this)
        editPort.setText(cfg.port.toString())
        editHost.setText(cfg.host)
        editDcIp.setText(cfg.dcIpList.joinToString("\n"))
        switchVerbose.isChecked = cfg.verbose
        switchAutoStart.isChecked = cfg.autoStart
    }

    private fun updateStatus() {
        val running = ProxyService.isRunning
        val cfg = ConfigManager.load(this)

        if (running) {
            statusIndicator.setBackgroundResource(R.drawable.circle_green)
            tvStatus.text = "Работает"
            tvStatusDetail.text = "SOCKS5 на ${cfg.host}:${cfg.port}"
            btnToggle.text = "Остановить"
            btnToggle.setBackgroundColor(ContextCompat.getColor(this, R.color.red))
            btnOpenTelegram.isEnabled = true

            val s = ProxyService.stats
            if (s != null) {
                tvStats.text =
                    "Соединений: ${s.connectionsTotal.get()} · WS: ${s.connectionsWs.get()} · TCP: ${s.connectionsTcpFallback.get()}\n" +
                            "↑ ${humanBytes(s.bytesUp.get())}  ↓ ${humanBytes(s.bytesDown.get())}"
            }
        } else {
            statusIndicator.setBackgroundResource(R.drawable.circle_gray)
            tvStatus.text = "Остановлен"
            tvStatusDetail.text = "Нажмите «Запустить»"
            btnToggle.text = "Запустить"
            btnToggle.setBackgroundColor(ContextCompat.getColor(this, R.color.tg_blue))
            btnOpenTelegram.isEnabled = false
            tvStats.text = ""
        }
    }

    private fun toggleProxy() {
        if (ProxyService.isRunning) {
            ProxyService.stop(this)
            Toast.makeText(this, "Прокси остановлен", Toast.LENGTH_SHORT).show()
        } else {
            if (!saveConfig()) return
            ProxyService.start(this)
            Toast.makeText(this, "Прокси запущен", Toast.LENGTH_SHORT).show()
        }
        lifecycleScope.launch {
            delay(500)
            updateStatus()
        }
    }

    private fun saveConfig(): Boolean {
        val portStr = editPort.text.toString().trim()
        val host    = editHost.text.toString().trim()
        val dcIpRaw = editDcIp.text.toString().trim()

        val port = portStr.toIntOrNull()
        if (port == null || port !in 1..65535) {
            Toast.makeText(this, "Неверный порт (1–65535)", Toast.LENGTH_SHORT).show()
            return false
        }
        if (host.isBlank()) {
            Toast.makeText(this, "Укажите хост", Toast.LENGTH_SHORT).show()
            return false
        }

        val dcIpList = dcIpRaw.split("\n", ",")
            .map { it.trim() }.filter { it.isNotEmpty() }

        try {
            ConfigManager.parseDcIpList(dcIpList)
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка DC IP: ${e.message}", Toast.LENGTH_LONG).show()
            return false
        }

        val cfg = ProxyConfig(
            port = port,
            host = host,
            dcIpList = dcIpList,
            verbose = switchVerbose.isChecked,
            autoStart = switchAutoStart.isChecked
        )
        ConfigManager.save(this, cfg)
        Toast.makeText(this, "Настройки сохранены", Toast.LENGTH_SHORT).show()
        return true
    }

    private fun openInTelegram() {
        val cfg = ConfigManager.load(this)
        val url = "tg://socks?server=${cfg.host}&port=${cfg.port}"
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: Exception) {
            Toast.makeText(this, "Telegram не найден", Toast.LENGTH_SHORT).show()
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this, Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    100
                )
            }
        }
    }

    private fun humanBytes(n: Long): String {
        var v = n.toDouble()
        for (unit in listOf("B", "KB", "MB", "GB")) {
            if (v < 1024) return "%.1f%s".format(v, unit)
            v /= 1024
        }
        return "%.1fTB".format(v)
    }
}