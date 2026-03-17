package com.tgwsproxy.proxy

import android.util.Log
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.withPermit

private val TAG = "ProxyCore"
private const val DIAG = "ProxyDIAG"

// ── Active bridge tracker ─────────────────────────────────────────────────
data class BridgeInfo(
    val label: String,
    val dc: Int,
    val isMedia: Boolean,
    val netAtOpen: String,
    val poolHit: Boolean,
    val poolAgeMs: Long,
    val openedAt: Long = System.currentTimeMillis()
)

object ActiveBridges {
    private val bridges = java.util.concurrent.ConcurrentHashMap<String, BridgeInfo>()

    fun open(info: BridgeInfo) {
        bridges[info.label] = info
        Log.i(DIAG, "BRIDGE_OPEN  dc=DC${info.dc}${if(info.isMedia)"m" else ""} " +
                "net=${info.netAtOpen} pool=${if(info.poolHit)"HIT(age=${info.poolAgeMs}ms)" else "MISS"} " +
                "active=${bridges.size} label=${info.label}")
    }

    fun close(label: String, bytesUp: Long, bytesDown: Long, reason: String, wsCloseCode: Int? = null) {
        val info = bridges.remove(label)
        val dur = if (info != null) System.currentTimeMillis() - info.openedAt else -1
        val netNow = if (isCellularNetwork) "CELL" else "WIFI"
        val netChanged = info != null && info.netAtOpen != netNow
        Log.i(DIAG, "BRIDGE_CLOSE dc=${if(info!=null)"DC${info.dc}${if(info.isMedia)"m" else ""}" else "?"} " +
                "dur=${dur}ms up=$bytesUp down=$bytesDown " +
                "reason=$reason ws_code=${wsCloseCode ?: "n/a"} " +
                "net_open=${info?.netAtOpen ?: "?"} net_close=$netNow net_changed=$netChanged " +
                "active=${bridges.size} label=$label")
    }

    fun count() = bridges.size

    fun onNetworkChange(from: String, to: String) {
        val snapshot = bridges.values.toList()
        Log.i(DIAG, "NET_CHANGE   from=$from to=$to active_bridges=${snapshot.size}")
        snapshot.forEach { b ->
            val age = System.currentTimeMillis() - b.openedAt
            Log.i(DIAG, "  alive_bridge: dc=DC${b.dc}${if(b.isMedia)"m" else ""} age=${age}ms label=${b.label}")
        }
    }
}

// Set to true when on mobile data (Megafon DPI bypass via TLS fragmentation).
// Set to false on Wi-Fi. Updated by ProxyService on network change.
@Volatile
var useTlsFragmentation: Boolean = false
@Volatile
var isCellularNetwork: Boolean = false

// ── Telegram IP ranges ──────────────────────────────────────────────────────
private val TG_RANGES = listOf(
    ipRange("185.76.151.0", "185.76.151.255"),
    ipRange("149.154.160.0", "149.154.175.255"),
    ipRange("91.105.192.0", "91.105.193.255"),
    ipRange("91.108.0.0",   "91.108.255.255")
)

// ── IP → (dc, isMedia) map ──────────────────────────────────────────────────
private val IP_TO_DC = mapOf(
    // IPv6 — Android использует сокращённую форму с ::
    // ::a = non-media, ::7 = media
    "2001:67c:4e8:f001::a"  to Pair(1, false),
    "2001:b28:f23d:f001::a" to Pair(1, false),
    "2001:67c:4e8:f001::7"  to Pair(1, true),
    "2001:b28:f23d:f001::7" to Pair(1, true),
    "2001:67c:4e8:f002::a"  to Pair(2, false),
    "2001:b28:f23d:f002::a" to Pair(2, false),
    "2001:67c:4e8:f002::7"  to Pair(2, true),
    "2001:b28:f23d:f002::7" to Pair(2, true),
    "2001:67c:4e8:f003::a"  to Pair(3, false),
    "2001:b28:f23d:f003::a" to Pair(3, false),
    "2001:67c:4e8:f003::7"  to Pair(3, true),
    "2001:b28:f23d:f003::7" to Pair(3, true),
    "2001:67c:4e8:f004::a"  to Pair(4, false),
    "2001:b28:f23d:f004::a" to Pair(4, false),
    "2001:67c:4e8:f004::7"  to Pair(4, true),
    "2001:b28:f23d:f004::7" to Pair(4, true),
    "2001:67c:4e8:f005::a"  to Pair(5, false),
    "2001:b28:f23d:f005::a" to Pair(5, false),
    "2001:67c:4e8:f005::7"  to Pair(5, true),
    "2001:b28:f23d:f005::7" to Pair(5, true),
    // DC1
    "149.154.175.50" to Pair(1, false), "149.154.175.51" to Pair(1, false),
    "149.154.175.53" to Pair(1, false), "149.154.175.54" to Pair(1, false),
    "149.154.175.52" to Pair(1, true),
    // DC2
    "149.154.167.41" to Pair(2, false), "149.154.167.50" to Pair(2, false),
    "149.154.167.35" to Pair(2, false),
    "149.154.167.51" to Pair(2, false), "149.154.167.220" to Pair(2, false),
    "95.161.76.100"  to Pair(2, false),
    "149.154.167.151" to Pair(2, true), "149.154.167.222" to Pair(2, true),
    "149.154.167.223" to Pair(2, true), "149.154.162.123" to Pair(2, true),
    // DC3
    "149.154.175.100" to Pair(3, false), "149.154.175.101" to Pair(3, false),
    "149.154.175.102" to Pair(3, true),
    // DC4
    "149.154.167.91" to Pair(4, false), "149.154.167.92" to Pair(4, false),
    "149.154.164.250" to Pair(4, true), "149.154.166.120" to Pair(4, true),
    "149.154.166.121" to Pair(4, true), "149.154.167.118" to Pair(4, true),
    "149.154.165.111" to Pair(4, true),
    // DC5
    "91.108.56.100" to Pair(5, false), "91.108.56.101" to Pair(5, false),
    "91.108.56.116" to Pair(5, false), "91.108.56.126" to Pair(5, false),
    "149.154.171.5"  to Pair(5, false),
    "91.108.56.102" to Pair(5, true), "91.108.56.128" to Pair(5, true),
    "91.108.56.151" to Pair(5, true),
    // DC203
    "91.105.192.100" to Pair(203, false)
)

private fun ipRange(from: String, to: String): Pair<Long, Long> {
    fun toLong(ip: String) = InetAddress.getByName(ip).address
        .fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
    return Pair(toLong(from), toLong(to))
}

private fun isTelegramIp(ip: String): Boolean {
    return try {
        val n = InetAddress.getByName(ip).address
            .fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
        TG_RANGES.any { (lo, hi) -> n in lo..hi }
    } catch (_: Exception) { false }
}

private fun isHttpTransport(data: ByteArray): Boolean {
    val s = data.take(8).toByteArray().toString(Charsets.ISO_8859_1)
    return s.startsWith("POST ") || s.startsWith("GET ") ||
            s.startsWith("HEAD ") || s.startsWith("OPTIONS ")
}

// ── MTProto DC extraction ──────────────────────────────────────────────────
private fun dcFromInit(data: ByteArray): Pair<Int?, Boolean> {
    return try {
        val key = data.copyOfRange(8, 40)
        val iv  = data.copyOfRange(40, 56)
        // AES-CTR keystream
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val keystream = cipher.update(ByteArray(64))
        val plain = ByteArray(8) { i -> (data[56 + i].toInt() xor keystream[56 + i].toInt()).toByte() }
        val proto = ByteBuffer.wrap(plain, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
        val dcRaw = ByteBuffer.wrap(plain, 4, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt()
        Log.d(TAG, "dcFromInit: proto=0x${proto.toString(16)} dc_raw=$dcRaw")
        if (proto == 0xEFEFEFEFL || proto == 0xEEEEEEEEL || proto == 0xDDDDDDDDL) {
            val dc = Math.abs(dcRaw)
            if (dc in 1..1000) return Pair(dc, dcRaw < 0)
        }
        Pair(null, false)
    } catch (e: Exception) {
        Log.d(TAG, "DC extraction failed: $e")
        Pair(null, false)
    }
}

private fun patchInitDc(data: ByteArray, dc: Int): ByteArray {
    if (data.size < 64) return data
    return try {
        val key = data.copyOfRange(8, 40)
        val iv  = data.copyOfRange(40, 56)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val ks = cipher.update(ByteArray(64))
        val newDc = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(dc.toShort()).array()
        val patched = data.copyOf()
        patched[60] = (ks[60].toInt() xor newDc[0].toInt()).toByte()
        patched[61] = (ks[61].toInt() xor newDc[1].toInt()).toByte()
        Log.d(TAG, "init patched: dc_id -> $dc")
        patched
    } catch (_: Exception) { data }
}

// ── MTProto message splitter ───────────────────────────────────────────────
class MsgSplitter(initData: ByteArray) {
    private val cipher: Cipher
    private var decBuf = ByteArray(0)

    init {
        val key = initData.copyOfRange(8, 40)
        val iv  = initData.copyOfRange(40, 56)
        cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        cipher.update(ByteArray(64)) // skip init packet
    }

    fun split(chunk: ByteArray): List<ByteArray> {
        val plain = cipher.update(chunk) ?: return listOf(chunk)
        val boundaries = mutableListOf<Int>()
        var pos = 0
        while (pos < plain.size) {
            val first = plain[pos].toInt() and 0xFF
            val (msgLen, headerLen) = if (first == 0x7F) {
                if (pos + 4 > plain.size) break
                val len = ((plain[pos+1].toInt() and 0xFF) or
                        ((plain[pos+2].toInt() and 0xFF) shl 8) or
                        ((plain[pos+3].toInt() and 0xFF) shl 16)) * 4
                Pair(len, 4)
            } else {
                Pair(first * 4, 1)
            }
            if (msgLen == 0 || pos + headerLen + msgLen > plain.size) break
            pos += headerLen + msgLen
            boundaries.add(pos)
        }
        if (boundaries.size <= 1) return listOf(chunk)
        val parts = mutableListOf<ByteArray>()
        var prev = 0
        for (b in boundaries) {
            parts.add(chunk.copyOfRange(prev, b))
            prev = b
        }
        if (prev < chunk.size) parts.add(chunk.copyOfRange(prev, chunk.size))
        return parts
    }
}

// ── WS domains ────────────────────────────────────────────────────────────
// When TLS fragmentation is active, kws*-1 domains are more reliable on Megafon
// (kws* returns 400 Bad Request despite successful TLS). Always prefer kws*-1.
fun wsDomains(dc: Int, isMedia: Boolean?): List<String> {
    val base = if (dc > 5) "telegram.org" else "web.telegram.org"
    // kws*-1 first when TLS frag is on (avoids 400 from kws* on Megafon)
    return if (useTlsFragmentation || isMedia == null || isMedia == true)
        listOf("kws$dc-1.$base", "kws$dc.$base")
    else
        listOf("kws$dc.$base", "kws$dc-1.$base")
}

// ── Stats ──────────────────────────────────────────────────────────────────
class ProxyStats {
    val connectionsTotal = AtomicInteger()
    val connectionsWs = AtomicInteger()
    val connectionsTcpFallback = AtomicInteger()
    val connectionsPassthrough = AtomicInteger()
    val wsErrors = AtomicInteger()
    val bytesUp = AtomicLong()
    val bytesDown = AtomicLong()
    val poolHits = AtomicInteger()
    val poolMisses = AtomicInteger()

    fun summary(): String {
        val hits = poolHits.get(); val misses = poolMisses.get()
        return "total=${connectionsTotal.get()} ws=${connectionsWs.get()} " +
                "tcp_fb=${connectionsTcpFallback.get()} pass=${connectionsPassthrough.get()} " +
                "err=${wsErrors.get()} " +
                "pool=$hits/${hits + misses} " +
                "up=${humanBytes(bytesUp.get())} down=${humanBytes(bytesDown.get())}"
    }

    private fun humanBytes(n: Long): String {
        var v = n.toDouble()
        for (unit in listOf("B","KB","MB","GB")) {
            if (v < 1024) return "%.1f%s".format(v, unit)
            v /= 1024
        }
        return "%.1fTB".format(v)
    }
}

// ── WS Pool ────────────────────────────────────────────────────────────────
private const val WS_POOL_SIZE    = 6
private const val WS_POOL_MAX_AGE_WIFI = 50_000L  // 50s — Telegram idle timeout ~60s
private const val WS_POOL_MAX_AGE_CELL = 12_000L  // 12s — cellular NAT kills idle faster
private const val WS_COOLDOWN_MS  = 60_000L
private fun poolMaxAge() = if (isCellularNetwork) WS_POOL_MAX_AGE_CELL else WS_POOL_MAX_AGE_WIFI

private data class PoolEntry(val ws: RawWebSocket, val createdAt: Long)

class WsPool {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Limit concurrent TLS handshakes to avoid congestion on mobile
    private val connectSemaphore = kotlinx.coroutines.sync.Semaphore(6)

    // ConcurrentLinkedDeque — pollFirst() атомарен, два потока не получат один элемент
    private val idle      = java.util.concurrent.ConcurrentHashMap<Pair<Int,Boolean>,
            java.util.concurrent.ConcurrentLinkedDeque<PoolEntry>>()
    private val refilling = java.util.concurrent.ConcurrentHashMap.newKeySet<Pair<Int,Boolean>>()

    // Глобальные cooldown/blacklist
    private val dcFailUntil = java.util.concurrent.ConcurrentHashMap<Pair<Int,Boolean>, Long>()
    private val wsBlacklist = java.util.concurrent.ConcurrentHashMap.newKeySet<Pair<Int,Boolean>>()

    val stats = ProxyStats()

    // ── Проверки для ClientHandler ──────────────────────────────────────────
    fun isBlacklisted(dc: Int, isMedia: Boolean) = Pair(dc, isMedia) in wsBlacklist
    fun isOnCooldown(dc: Int, isMedia: Boolean): Boolean {
        val until = dcFailUntil[Pair(dc, isMedia)] ?: return false
        return System.currentTimeMillis() < until
    }
    fun markAllRedirects(dc: Int, isMedia: Boolean) {
        wsBlacklist.add(Pair(dc, isMedia))
        Log.w(TAG, "DC$dc${if(isMedia)"m" else ""} blacklisted (all 302)")
    }
    fun markFailed(dc: Int, isMedia: Boolean) {
        dcFailUntil[Pair(dc, isMedia)] = System.currentTimeMillis() + WS_COOLDOWN_MS
        Log.i(TAG, "DC$dc${if(isMedia)"m" else ""} cooldown ${WS_COOLDOWN_MS/1000}s")
    }
    fun markSuccess(dc: Int, isMedia: Boolean) { dcFailUntil.remove(Pair(dc, isMedia)) }

    // ── Получить соединение из пула ─────────────────────────────────────────
    // pollFirst() атомарен — гарантирует что два потока не возьмут один элемент
    /** Returns (ws, ageMs) or (null, -1) */
    fun getWithAge(dc: Int, isMedia: Boolean, targetIp: String, domains: List<String>): Pair<RawWebSocket?, Long> {
        val key    = Pair(dc, isMedia)
        val now    = System.currentTimeMillis()
        val bucket = idle.getOrPut(key) { java.util.concurrent.ConcurrentLinkedDeque() }

        while (true) {
            val entry = bucket.pollFirst() ?: break   // null → пуст
            val age   = now - entry.createdAt
            val maxAge = poolMaxAge()
            if (age > maxAge) {
                Log.i(DIAG, "POOL_GET     dc=DC$dc${if(isMedia)"m" else ""} age=${age}ms maxAge=${maxAge}ms action=DISCARD_AGE")
                scope.launch { try { entry.ws.close() } catch (_: Exception) {} }
                continue
            }
            if (entry.ws.closed) {
                Log.i(DIAG, "POOL_GET     dc=DC$dc${if(isMedia)"m" else ""} age=${age}ms action=DISCARD_CLOSED")
                scope.launch { try { entry.ws.close() } catch (_: Exception) {} }
                continue
            }
            stats.poolHits.incrementAndGet()
            Log.i(DIAG, "POOL_GET     dc=DC$dc${if(isMedia)"m" else ""} age=${age}ms action=REUSE left=${bucket.size}")
            scheduleRefill(key, targetIp, domains)
            return Pair(entry.ws, age)
        }
        stats.poolMisses.incrementAndGet()
        Log.i(DIAG, "POOL_GET     dc=DC$dc${if(isMedia)"m" else ""} age=-1 action=EMPTY")
        scheduleRefill(key, targetIp, domains)
        return Pair(null, -1)
    }

    @Deprecated("Use getWithAge", ReplaceWith("getWithAge(dc, isMedia, targetIp, domains).first"))
    fun get(dc: Int, isMedia: Boolean, targetIp: String, domains: List<String>): RawWebSocket? =
        getWithAge(dc, isMedia, targetIp, domains).first

    // ── Заполнение пула ─────────────────────────────────────────────────────
    private fun scheduleRefill(key: Pair<Int,Boolean>, targetIp: String, domains: List<String>) {
        if (!refilling.add(key)) return   // уже идёт refill
        scope.launch {
            try {
                val bucket = idle.getOrPut(key) { java.util.concurrent.ConcurrentLinkedDeque() }
                val needed = WS_POOL_SIZE - bucket.size
                if (needed <= 0) return@launch
                val jobs = (0 until needed).map { async { connectOne(targetIp, domains) } }
                jobs.forEach { job ->
                    try {
                        val ws = job.await() ?: return@forEach
                        bucket.addLast(PoolEntry(ws, System.currentTimeMillis()))
                    } catch (_: Exception) {}
                }
                Log.d(TAG, "WS pool refilled DC${key.first}${if(key.second)"m" else ""}: ${bucket.size} ready")
            } finally {
                refilling.remove(key)
            }
        }
    }

    private suspend fun connectOne(targetIp: String, domains: List<String>): RawWebSocket? {
        return connectSemaphore.withPermit {
            for (domain in domains) {
                try {
                    return@withPermit RawWebSocket.connect(
                        targetIp, domain,
                        timeoutMs = if (useTlsFragmentation) 5_000 else 8_000,
                        useTlsFragmentation = useTlsFragmentation
                    )
                } catch (e: WsHandshakeError) {
                    Log.w(TAG, "pool connectOne $domain → HTTP ${e.statusCode}")
                    if (e.isRedirect || e.statusCode == 400) continue
                    return@withPermit null
                } catch (e: Exception) {
                    Log.w(TAG, "pool connectOne $domain → $e")
                    continue
                }
            }
            null
        }
    }

    // ── Очистка при смене сети ───────────────────────────────────────────────
    fun clear() {
        val poolSize = idle.values.sumOf { it.size }
        Log.i(DIAG, "POOL_CLEAR   pool_size=$poolSize active_bridges=${ActiveBridges.count()}")
        idle.values.forEach { bucket ->
            var entry = bucket.pollFirst()
            while (entry != null) {
                val ws = entry.ws
                scope.launch { try { ws.close() } catch (_: Exception) {} }
                entry = bucket.pollFirst()
            }
        }
        idle.clear()
        refilling.clear()
        dcFailUntil.clear()
        wsBlacklist.clear()
        Log.i(TAG, "WS pool cleared (network change)")
    }

    suspend fun warmup(dcOpt: Map<Int, String>) {
        // On mobile, only warm DC2 and DC4 — DC1/3/5 are
        // consistently blocked on Megafon and waste semaphore slots + timeouts
        val onMobile = isCellularNetwork
        val dcsToWarm = if (onMobile) {
            dcOpt.filter { it.key == 2 || it.key == 4 }
        } else {
            dcOpt
        }
        for ((dc, targetIp) in dcsToWarm) {
            for (isMedia in listOf(false, true)) {
                scheduleRefill(Pair(dc, isMedia), targetIp, wsDomains(dc, isMedia))
            }
        }
        Log.i(TAG, "WS pool warmup started for ${dcsToWarm.size} DCs${if (onMobile) " (mobile, DC2+DC4 only)" else ""}")
    }
}

// ── SOCKS5 helper ──────────────────────────────────────────────────────────
private fun socks5Reply(status: Int): ByteArray =
    byteArrayOf(0x05, status.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

// ── Main client handler ────────────────────────────────────────────────────
class ClientHandler(
    private val socket: Socket,
    private val dcOpt: Map<Int, String>,
    private val pool: WsPool,
    private val verbose: Boolean
) {
    private val stats get() = pool.stats
    private val label = "${socket.inetAddress.hostAddress}:${socket.port}"

    suspend fun handle() = withContext(Dispatchers.IO) {
        stats.connectionsTotal.incrementAndGet()
        try {
            val inp = socket.getInputStream()
            val out = socket.getOutputStream()

            // ── SOCKS5 greeting ──
            val hdr = ByteArray(2).also { readExactly(inp, it) }
            if (hdr[0] != 5.toByte()) {
                Log.d(TAG, "[$label] not SOCKS5 (ver=${hdr[0]})")
                return@withContext
            }
            val nmethods = hdr[1].toInt() and 0xFF
            ByteArray(nmethods).also { readExactly(inp, it) }
            out.write(byteArrayOf(0x05, 0x00)); out.flush()

            // ── SOCKS5 CONNECT ──
            val req = ByteArray(4).also { readExactly(inp, it) }
            val cmd = req[1].toInt()
            val atyp = req[3].toInt()
            if (cmd != 1) {
                out.write(socks5Reply(0x07)); out.flush()
                return@withContext
            }

            val dst = when (atyp) {
                1 -> { // IPv4
                    val raw = ByteArray(4).also { readExactly(inp, it) }
                    InetAddress.getByAddress(raw).hostAddress ?: return@withContext
                }
                3 -> { // domain
                    val dlen = inp.read()
                    ByteArray(dlen).also { readExactly(inp, it) }.toString(Charsets.UTF_8)
                }
                4 -> { // IPv6
                    val raw = ByteArray(16).also { readExactly(inp, it) }
                    InetAddress.getByAddress(raw).hostAddress ?: return@withContext
                }
                else -> {
                    out.write(socks5Reply(0x08)); out.flush()
                    return@withContext
                }
            }

            val portBytes = ByteArray(2).also { readExactly(inp, it) }
            val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            // IPv6 — попробуем резолвить в IPv4
            if (dst.contains(':')) {
                val cleanDst = dst.trimStart('[').trimEnd(']')
                val dcInfo = IP_TO_DC[cleanDst]
                if (dcInfo != null) {
                    val (ipv6Dc, ipv6IsMedia) = dcInfo
                    if (ipv6Dc in dcOpt) {
                        val ipv4Target = dcOpt[ipv6Dc]!!
                        Log.d(TAG, "[$label] IPv6 $cleanDst -> DC$ipv6Dc IPv4 $ipv4Target")
                        try {
                            val remote = Socket()
                            try {
                                remote.connect(InetSocketAddress(ipv4Target, port), 10_000)
                                out.write(socks5Reply(0x00)); out.flush()
                                bridgeTcpTcp(inp, out, remote.getInputStream(), remote.getOutputStream())
                            } finally {
                                try { remote.close() } catch (_: Exception) {}
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "[$label] IPv6->IPv4 fallback failed: $e")
                            out.write(socks5Reply(0x05)); out.flush()
                        }
                        return@withContext
                    }
                }
                Log.e(TAG, "[$label] IPv6 $cleanDst — no mapping, dropping")
                out.write(socks5Reply(0x05)); out.flush()
                return@withContext
            }

            // ── Non-Telegram → passthrough ──
            if (!isTelegramIp(dst)) {
                stats.connectionsPassthrough.incrementAndGet()
                Log.d(TAG, "[$label] passthrough -> $dst:$port")
                try {
                    val remote = Socket()
                    try {
                        remote.connect(InetSocketAddress(dst, port), 10_000)
                        out.write(socks5Reply(0x00)); out.flush()
                        bridgeTcpTcp(inp, out, remote.getInputStream(), remote.getOutputStream())
                    } finally {
                        try { remote.close() } catch (_: Exception) {}
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "[$label] passthrough failed: $e")
                    out.write(socks5Reply(0x05)); out.flush()
                }
                return@withContext
            }

            // ── Telegram DC: accept and read init ──
            out.write(socks5Reply(0x00)); out.flush()

            var init = ByteArray(64)
            try {
                readExactly(inp, init)
            } catch (e: Exception) {
                Log.d(TAG, "[$label] client disconnected before init")
                return@withContext
            }

            if (isHttpTransport(init)) {
                Log.d(TAG, "[$label] HTTP transport rejected")
                return@withContext
            }

            // ── Extract DC ID ──
            var (dc, isMedia) = dcFromInit(init)
            var initPatched = false

            if (dc == null && dst in IP_TO_DC) {
                val mapped = IP_TO_DC[dst]!!
                dc = mapped.first
                isMedia = mapped.second
                if (dc in dcOpt) {
                    init = patchInitDc(init, if (isMedia) -dc else dc)
                    initPatched = true
                }
            }

            if (dc == null || dc !in dcOpt) {
                Log.w(TAG, "[$label] unknown DC$dc for $dst:$port -> TCP passthrough")
                tcpFallback(inp, out, dst, port, init)
                return@withContext
            }

            val mediaTag = when {
                isMedia == true -> " media"
                isMedia == null -> " media?"
                else -> ""
            }

            Log.i(DIAG, "CONNECT      dc=DC$dc$mediaTag dst=$dst:$port net=${if(isCellularNetwork)"CELL" else "WIFI"} label=$label")

            // ── WS blacklist check ──
            if (pool.isBlacklisted(dc, isMedia ?: false)) {
                Log.d(TAG, "[$label] DC$dc$mediaTag WS blacklisted -> TCP $dst:$port")
                tcpFallback(inp, out, dst, port, init)
                return@withContext
            }

            // ── Cooldown check ──
            if (pool.isOnCooldown(dc, isMedia ?: false)) {
                Log.d(TAG, "[$label] DC$dc$mediaTag WS cooldown -> TCP")
                tcpFallback(inp, out, dst, port, init)
                return@withContext
            }

            // ── Try WebSocket ──
            val domains = wsDomains(dc, isMedia)
            val target = dcOpt[dc]!!
            var ws: RawWebSocket? = null
            var wsFailed302 = false
            var allRedirects = true
            var poolHit = false
            var poolAgeMs = -1L

            val (poolWs, poolAge) = pool.getWithAge(dc, isMedia ?: false, target, domains)
            if (poolWs != null) {
                ws = poolWs
                poolHit = true
                poolAgeMs = poolAge
                Log.i(TAG, "[$label] DC$dc$mediaTag ($dst:$port) -> pool hit via $target")
            } else {
                for (domain in domains) {
                    val url = "wss://$domain/apiws"
                    Log.i(TAG, "[$label] DC$dc$mediaTag ($dst:$port) -> $url via $target")
                    val connectStart = System.currentTimeMillis()
                    try {
                        ws = RawWebSocket.connect(target, domain, timeoutMs = if (useTlsFragmentation) 20_000 else 10_000, useTlsFragmentation = useTlsFragmentation)
                        val connectMs = System.currentTimeMillis() - connectStart
                        Log.i(DIAG, "WS_CONNECT   dc=DC$dc$mediaTag domain=$domain dur=${connectMs}ms net=${if(isCellularNetwork)"CELL" else "WIFI"}")
                        allRedirects = false
                        break
                    } catch (e: WsHandshakeError) {
                        val connectMs = System.currentTimeMillis() - connectStart
                        stats.wsErrors.incrementAndGet()
                        if (e.isRedirect) {
                            wsFailed302 = true
                            Log.w(TAG, "[$label] DC$dc$mediaTag got ${e.statusCode} from $domain -> ${e.location ?: "?"} (${connectMs}ms)")
                        } else {
                            allRedirects = false
                            Log.w(TAG, "[$label] DC$dc$mediaTag WS handshake: ${e.statusLine} (${connectMs}ms)")
                        }
                    } catch (e: Exception) {
                        val connectMs = System.currentTimeMillis() - connectStart
                        stats.wsErrors.incrementAndGet()
                        allRedirects = false
                        Log.w(TAG, "[$label] DC$dc$mediaTag WS connect failed: $e (${connectMs}ms)")
                    }
                }
            }

            // ── WS failed → fallback ──
            if (ws == null) {
                if (wsFailed302 && allRedirects) {
                    pool.markAllRedirects(dc, isMedia ?: false)
                } else {
                    pool.markFailed(dc, isMedia ?: false)
                }
                Log.i(DIAG, "WS_FAIL      dc=DC$dc$mediaTag -> TCP_FALLBACK net=${if(isCellularNetwork)"CELL" else "WIFI"}")
                Log.i(TAG, "[$label] DC$dc$mediaTag -> TCP fallback to $dst:$port")
                val ok = tcpFallback(inp, out, dst, port, init)
                if (ok) Log.i(TAG, "[$label] DC$dc$mediaTag TCP fallback closed")
                return@withContext
            }

            // ── WS success ──
            pool.markSuccess(dc, isMedia ?: false)
            stats.connectionsWs.incrementAndGet()

            // Clear pool/connect soTimeout before long-lived bridge.
            // Without this, pool connections (soTimeout=5s) kill the bridge
            // on any idle pause >5s between MTProto messages.
            ws.clearReadTimeout()
            Log.i(DIAG, "TIMEOUT_CLEAR dc=DC$dc$mediaTag pool=$poolHit label=$label")

            val splitter = if (initPatched) {
                try { MsgSplitter(init) } catch (_: Exception) { null }
            } else null

            ws.send(init)
            Log.d(TAG, "[$label] init sent (${init.size}b), starting bridge")
            ActiveBridges.open(BridgeInfo(
                label = label,
                dc = dc,
                isMedia = isMedia ?: false,
                netAtOpen = if (isCellularNetwork) "CELL" else "WIFI",
                poolHit = poolHit,
                poolAgeMs = poolAgeMs
            ))
            val result = bridgeWsTcp(inp, out, ws, label, splitter, dc, isMedia ?: false)

            // ── Log retry candidate for future implementation ──
            if (isCellularNetwork && result.bytesDown == 0L && result.durationMs < 15_000 && result.reason != "LOCAL_EOF") {
                Log.i(DIAG, "RETRY_CANDIDATE dc=DC$dc$mediaTag dur=${result.durationMs}ms down=0 reason=${result.reason}")
            }

        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "[$label] unexpected: $e")
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /** Result of a bridge session — used for retry decisions */
    data class BridgeResult(val durationMs: Long, val bytesUp: Long, val bytesDown: Long, val reason: String)

    private suspend fun bridgeWsTcp(
        inp: java.io.InputStream,
        out: java.io.OutputStream,
        ws: RawWebSocket,
        label: String,
        splitter: MsgSplitter?,
        dc: Int,
        isMedia: Boolean
    ): BridgeResult = coroutineScope {
        Log.i(TAG, "[$label] bridge started")
        val startTime = System.currentTimeMillis()
        var localUp = 0L
        var localDown = 0L
        var closeReason = "UNKNOWN"
        var wsCloseCode: Int? = null

        // ── Keepalive ping — prevents NAT from killing idle WS on cellular ──
        val pingJob = if (isCellularNetwork) {
            launch(Dispatchers.IO) {
                try {
                    while (true) {
                        delay(10_000)
                        if (ws.closed) break
                        ws.sendPing()
                        Log.d(TAG, "[$label] keepalive ping sent")
                    }
                } catch (_: CancellationException) {
                    // normal — bridge ending
                } catch (e: Exception) {
                    Log.d(TAG, "[$label] ping error: ${e.javaClass.simpleName}")
                }
            }
        } else null

        val upJob = launch(Dispatchers.IO) {
            val buf = ByteArray(131072)
            var firstChunk = true
            try {
                while (true) {
                    val n = inp.read(buf)
                    if (n == -1) { closeReason = "LOCAL_EOF"; Log.d(TAG, "[$label] up: client EOF"); break }
                    val chunk = buf.copyOf(n)
                    if (firstChunk) {
                        firstChunk = false
                        val hex = chunk.take(64).joinToString(" ") { "%02x".format(it) }
                        Log.i(TAG, "[$label] first up frame: ${n}b | $hex")
                    }
                    localUp += n
                    stats.bytesUp.addAndGet(n.toLong())
                    if (splitter != null) {
                        val parts = splitter.split(chunk)
                        if (parts.size > 1) ws.sendBatch(parts) else ws.send(parts[0])
                    } else {
                        ws.send(chunk)
                    }
                }
            } catch (e: CancellationException) {
                if (closeReason == "UNKNOWN") closeReason = "UP_CANCELLED"
                throw e
            } catch (e: Exception) {
                if (closeReason == "UNKNOWN") closeReason = "UP_ERR:${e.javaClass.simpleName}"
                Log.d(TAG, "[$label] up error: $e")
            }
        }
        val downJob = launch(Dispatchers.IO) {
            var firstFrame = true
            try {
                while (true) {
                    val data = ws.recv() ?: {
                        closeReason = "WS_CLOSED(${ws.closeInitiator ?: "?"})"
                        wsCloseCode = ws.lastCloseCode
                        Log.d(TAG, "[$label] down: WS closed (code=${ws.lastCloseCode} reason=${ws.lastCloseReason} initiator=${ws.closeInitiator})")
                        null
                    }() ?: break
                    localDown += data.size
                    stats.bytesDown.addAndGet(data.size.toLong())
                    if (firstFrame) {
                        firstFrame = false
                        val hex = data.take(64).joinToString(" ") { "%02x".format(it) }
                        Log.i(TAG, "[$label] first down frame: ${data.size}b | $hex")
                    }
                    out.write(data)
                    out.flush()
                }
            } catch (e: CancellationException) {
                if (closeReason == "UNKNOWN") closeReason = "DOWN_CANCELLED"
                throw e
            } catch (e: Exception) {
                if (closeReason == "UNKNOWN") {
                    closeReason = "DOWN_ERR:${e.javaClass.simpleName}"
                    wsCloseCode = ws.lastCloseCode
                    if (ws.closeInitiator == "ERROR") {
                        closeReason += "(ws:${ws.lastCloseReason?.take(40) ?: "?"})"
                    }
                }
                Log.d(TAG, "[$label] down error: $e")
            }
        }
        try {
            select<Unit> {
                upJob.onJoin {}
                downJob.onJoin {}
            }
        } finally {
            val dur = System.currentTimeMillis() - startTime
            ActiveBridges.close(label, localUp, localDown, closeReason, wsCloseCode)
            Log.i(TAG, "[$label] bridge closed (up=$localUp down=$localDown reason=$closeReason dur=${dur}ms)")
            pingJob?.cancel()
            upJob.cancel(); downJob.cancel()
            try { ws.close() } catch (_: Exception) {}
        }
        val dur = System.currentTimeMillis() - startTime
        BridgeResult(dur, localUp, localDown, closeReason)
    }

    private suspend fun bridgeTcpTcp(
        inp: java.io.InputStream, out: java.io.OutputStream,
        remoteIn: java.io.InputStream, remoteOut: java.io.OutputStream
    ) = coroutineScope {
        val upJob = launch(Dispatchers.IO) {
            try {
                val buf = ByteArray(65536)
                while (true) {
                    val n = inp.read(buf)
                    if (n == -1) break
                    stats.bytesUp.addAndGet(n.toLong())
                    remoteOut.write(buf, 0, n); remoteOut.flush()
                }
            } catch (_: Exception) {}
        }
        val downJob = launch(Dispatchers.IO) {
            try {
                val buf = ByteArray(65536)
                while (true) {
                    val n = remoteIn.read(buf)
                    if (n == -1) break
                    stats.bytesDown.addAndGet(n.toLong())
                    out.write(buf, 0, n); out.flush()
                }
            } catch (_: Exception) {}
        }
        try {
            select<Unit> {
                upJob.onJoin {}
                downJob.onJoin {}
            }
        } finally {
            upJob.cancel(); downJob.cancel()
        }
    }

    private suspend fun tcpFallback(
        inp: java.io.InputStream, out: java.io.OutputStream,
        dst: String, port: Int, init: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        val remote = Socket()
        try {
            remote.connect(InetSocketAddress(dst, port), 10_000)
            val rOut = remote.getOutputStream()
            val rIn  = remote.getInputStream()
            stats.connectionsTcpFallback.incrementAndGet()
            rOut.write(init); rOut.flush()
            bridgeTcpTcp(inp, out, rIn, rOut)
            true
        } catch (e: Exception) {
            Log.w(TAG, "[$label] TCP fallback to $dst:$port failed: $e")
            false
        } finally {
            try { remote.close() } catch (_: Exception) {}
        }
    }

    private fun readExactly(inp: java.io.InputStream, buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = inp.read(buf, offset, buf.size - offset)
            if (n == -1) throw Exception("Connection closed")
            offset += n
        }
    }
}