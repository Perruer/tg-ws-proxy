package com.tgwsproxy.proxy

import android.app.*
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.tgwsproxy.ConfigManager
import com.tgwsproxy.R
import com.tgwsproxy.ui.MainActivity
import kotlinx.coroutines.*
import java.net.ServerSocket

private val TAG = "ProxyService"

class ProxyService : Service() {

    companion object {
        const val ACTION_START  = "com.tgwsproxy.START"
        const val ACTION_STOP   = "com.tgwsproxy.STOP"
        const val CHANNEL_ID    = "proxy_channel"
        const val NOTIF_ID      = 1

        @Volatile var isRunning = false
        @Volatile var stats: ProxyStats? = null

        fun start(context: Context) {
            val intent = Intent(context, ProxyService::class.java).apply {
                action = ACTION_START
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ProxyService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private var serverJob: Job? = null
    private val pool = WsPool()
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var wakeLock: PowerManager.WakeLock? = null
    private var connectivityManager: ConnectivityManager? = null
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val onCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
            val onWifi     = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            val frag = onCellular && !onWifi
            val wasCellular = isCellularNetwork
            isCellularNetwork = frag
            if (useTlsFragmentation != frag) {
                useTlsFragmentation = frag
                Log.i(TAG, "Network changed: cellular=$onCellular wifi=$onWifi → tlsFrag=$frag")
                ActiveBridges.onNetworkChange(
                    from = if (wasCellular) "CELL" else "WIFI",
                    to = if (frag) "CELL" else "WIFI"
                )
                // Flush pool so next connections use correct mode
                pool.clear()
            }
        }
        override fun onLost(network: Network) {
            Log.i(TAG, "Network lost — keeping tlsFrag=$useTlsFragmentation")
            ActiveBridges.onNetworkChange(
                from = if (isCellularNetwork) "CELL" else "WIFI",
                to = "LOST"
            )
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startProxy()
            ACTION_STOP  -> stopProxy()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopProxy()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startProxy() {
        if (isRunning) return
        val config = ConfigManager.load(this)

        val dcOpt = try {
            ConfigManager.parseDcIpList(config.dcIpList)
        } catch (e: Exception) {
            Log.e(TAG, "Bad config: $e")
            stopSelf()
            return
        }

        startForeground(NOTIF_ID, buildNotification("Запускается..."))

        // WakeLock — не даёт процессору засыпать пока прокси работает
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "TgWsProxy::ProxyWakeLock"
        )
        wakeLock?.acquire(4 * 60 * 60 * 1000L)  // 4h max, re-acquired on restart

        isRunning = true
        stats = pool.stats

        // Detect current network type and monitor changes
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager?.registerNetworkCallback(req, networkCallback)
        // Set initial value based on current active network
        val activeCaps = connectivityManager?.activeNetwork
            ?.let { connectivityManager?.getNetworkCapabilities(it) }
        useTlsFragmentation = activeCaps != null &&
                activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        isCellularNetwork = useTlsFragmentation
        Log.i(TAG, "Initial network: tlsFrag=$useTlsFragmentation")

        serverJob = serviceScope.launch {
            pool.warmup(dcOpt)

            launch {
                while (isActive) {
                    delay(60_000)
                    Log.i(TAG, "stats: ${pool.stats.summary()}")
                    updateNotification("Работает · ${pool.stats.summary().take(40)}")
                }
            }

            try {
                val serverSocket = ServerSocket()
                serverSocket.reuseAddress = true
                serverSocket.soTimeout = 0
                serverSocket.bind(java.net.InetSocketAddress(config.host, config.port))
                Log.i(TAG, "=".repeat(50))
                Log.i(TAG, "  TG WS Proxy listening on ${config.host}:${config.port}")
                Log.i(TAG, "=".repeat(50))
                updateNotification("Работает на порту ${config.port}")

                serverSocket.soTimeout = 5_000
                while (isActive) {
                    try {
                        val clientSocket = serverSocket.accept()
                        clientSocket.soTimeout = 30_000
                        launch {
                            ClientHandler(clientSocket, dcOpt, pool, config.verbose).handle()
                        }
                    } catch (e: java.net.SocketTimeoutException) {
                        continue
                    }
                }
                serverSocket.close()
            } catch (e: Exception) {
                if (isActive) {
                    Log.e(TAG, "Server error: $e")
                    updateNotification("Ошибка: ${e.message}")
                }
            }
        }
    }

    private fun stopProxy() {
        isRunning = false
        stats = null
        serverJob?.cancel()
        try { connectivityManager?.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
        connectivityManager = null
        serverJob = null
        wakeLock?.release()
        wakeLock = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Proxy stopped")
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "TG WS Proxy",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Статус прокси-сервера"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }

    private fun buildNotification(status: String): Notification {
        val mainIntent = Intent(this, MainActivity::class.java)
        val pendingMain = PendingIntent.getActivity(
            this, 0, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = Intent(this, ProxyService::class.java).apply { action = ACTION_STOP }
        val pendingStop = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TG WS Proxy")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_proxy_notif)
            .setContentIntent(pendingMain)
            .addAction(0, "Остановить", pendingStop)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val notif = buildNotification(status)
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, notif)
    }
}