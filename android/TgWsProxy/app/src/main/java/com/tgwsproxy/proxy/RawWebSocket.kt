package com.tgwsproxy.proxy

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.SSLContext

private val TAG = "RawWebSocket"
private val RNG = SecureRandom()

// System CA SSL context — verifies server certificates normally
private val SSL_CTX: SSLContext by lazy {
    SSLContext.getInstance("TLS").also { it.init(null, null, null) }
}

class WsHandshakeError(
    val statusCode: Int,
    val statusLine: String,
    val headers: Map<String, String> = emptyMap(),
    val location: String? = null
) : Exception("HTTP $statusCode: $statusLine") {
    val isRedirect get() = statusCode in listOf(301, 302, 303, 307, 308)
}

// ---------------------------------------------------------------------------
// TLS-fragmentation OutputStream
//
// DPI (Megafon) looks for SNI in the first TLS record (type 0x16 = Handshake,
// which contains ClientHello). We split that first record into multiple TCP
// segments to prevent DPI from reassembling it in a single read.
//
// Split strategy:
//   write #1: TLS record header bytes [0..2]  (type + TLS version)  → flush
//   write #2: TLS record header bytes [3..4]  (payload length)      → flush
//   write #3: first 1 byte of ClientHello body                       → flush
//   write #4: rest of ClientHello body
//   All subsequent data: passthrough unchanged.
//
// TCP_NODELAY must be set on the underlying socket so each write() becomes
// an individual TCP segment.
// ---------------------------------------------------------------------------
private class TlsFragmentingStream(
    private val realOut: OutputStream
) : OutputStream() {

    private enum class State { HEADER, BODY_FIRST_BYTE, BODY_REST, PASSTHROUGH }

    private var state = State.HEADER
    private val headerBuf = ByteArray(5)
    private var headerPos = 0
    private var bodyRemaining = 0

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(src: ByteArray, off: Int, len: Int) {
        if (state == State.PASSTHROUGH) {
            realOut.write(src, off, len)
            return
        }
        var pos = off
        val end = off + len
        while (pos < end) {
            when (state) {
                State.HEADER -> {
                    val need = 5 - headerPos
                    val take = minOf(need, end - pos)
                    System.arraycopy(src, pos, headerBuf, headerPos, take)
                    headerPos += take
                    pos += take
                    if (headerPos == 5) {
                        val recordType = headerBuf[0].toInt() and 0xFF
                        val bodyLen = ((headerBuf[3].toInt() and 0xFF) shl 8) or
                                (headerBuf[4].toInt() and 0xFF)
                        if (recordType == 0x16) {
                            // ClientHello — fragment header into 2 writes
                            realOut.write(headerBuf, 0, 3); realOut.flush()
                            Thread.sleep(2)
                            realOut.write(headerBuf, 3, 2); realOut.flush()
                            Thread.sleep(2)
                            bodyRemaining = bodyLen
                            state = State.BODY_FIRST_BYTE
                            Log.d(TAG, "TLS frag: ClientHello len=$bodyLen, header split done")
                        } else {
                            // Not a Handshake record — write header as-is and stop
                            realOut.write(headerBuf, 0, 5)
                            state = State.PASSTHROUGH
                            if (pos < end) realOut.write(src, pos, end - pos)
                            return
                        }
                    }
                }
                State.BODY_FIRST_BYTE -> {
                    // send exactly 1 byte of ClientHello body
                    realOut.write(src, pos, 1); realOut.flush()
                    Thread.sleep(2)
                    pos += 1
                    bodyRemaining -= 1
                    state = if (bodyRemaining > 0) State.BODY_REST else State.PASSTHROUGH
                    Log.d(TAG, "TLS frag: first body byte sent")
                }
                State.BODY_REST -> {
                    val take = minOf(end - pos, bodyRemaining)
                    realOut.write(src, pos, take)
                    pos += take
                    bodyRemaining -= take
                    if (bodyRemaining == 0) {
                        state = State.PASSTHROUGH
                        Log.d(TAG, "TLS frag: ClientHello body complete")
                        if (pos < end) realOut.write(src, pos, end - pos)
                        return
                    }
                }
                State.PASSTHROUGH -> {
                    realOut.write(src, pos, end - pos)
                    return
                }
            }
        }
    }

    override fun flush() = realOut.flush()
    override fun close() = realOut.close()
}


// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------
class RawWebSocket(
    private val input: InputStream,
    private val output: OutputStream,
    private val underlyingSockets: List<java.io.Closeable> = emptyList(),
    @Volatile var closed: Boolean = false
) {
    // ── Close diagnostics ────────────────────────────────────────────────────
    @Volatile var lastCloseCode: Int? = null
    @Volatile var lastCloseReason: String? = null
    /** "REMOTE" = server sent close frame, "LOCAL" = we initiated, "ERROR" = exception */
    @Volatile var closeInitiator: String? = null

    /**
     * Remove the read timeout inherited from pool/connect phase.
     * Must be called before using this WS for a long-lived bridge,
     * otherwise soTimeout from connectOne (5s) kills the bridge
     * on any idle pause >5s between MTProto messages.
     */
    fun clearReadTimeout() {
        underlyingSockets.forEach { s ->
            try {
                when (s) {
                    is javax.net.ssl.SSLSocket -> { s.soTimeout = 0 }
                    is Socket -> { s.soTimeout = 0 }
                }
            } catch (_: Exception) {}
        }
    }

    companion object {
        const val OP_CONTINUATION = 0x0
        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA

        /**
         * Connect to [ip]:443, perform fragmented TLS handshake with SNI=[domain],
         * then upgrade to WebSocket.
         *
         * @param useTlsFragmentation  when true, splits ClientHello across multiple TCP
         *                              segments to bypass SNI-based DPI (Megafon).
         */
        suspend fun connect(
            ip: String,
            domain: String,
            path: String = "/apiws",
            timeoutMs: Int = 10_000,
            useTlsFragmentation: Boolean = false
        ): RawWebSocket = withContext(Dispatchers.IO) {

            if (!useTlsFragmentation) {
                // Fast path: SSLSocket (no fragmentation needed, e.g. Wi-Fi)
                return@withContext connectSslSocket(ip, domain, path, timeoutMs)
            }

            // 1. Plain TCP socket with TCP_NODELAY so every write → own segment
            val tcp = Socket()
            try {
                tcp.tcpNoDelay = true
                tcp.soTimeout = timeoutMs
                tcp.connect(InetSocketAddress(ip, 443), timeoutMs)

                val rawOut = tcp.getOutputStream()
                val rawIn  = tcp.getInputStream()

                Log.i(TAG, "TLS frag enabled → $domain ($ip)")

                // Use a proxy socket so SSLSocket uses TlsFragmentingStream for output.
                val proxySocket = object : Socket() {
                    override fun getInputStream() = rawIn
                    override fun getOutputStream(): OutputStream = TlsFragmentingStream(rawOut)
                    override fun isClosed() = tcp.isClosed
                    override fun isConnected() = tcp.isConnected
                }

                val sslSock = (SSL_CTX.socketFactory.createSocket(
                    proxySocket, domain, 443, false
                ) as javax.net.ssl.SSLSocket).also { s ->
                    s.useClientMode = true
                    s.soTimeout = timeoutMs
                    val p = s.sslParameters
                    p.serverNames = listOf(javax.net.ssl.SNIHostName(domain))
                    s.sslParameters = p
                    s.startHandshake()
                }
                Log.i(TAG, "TLS ok (frag): ${sslSock.session.protocol} / ${sslSock.session.cipherSuite} sni=$domain")

                val sslIn  = sslSock.inputStream
                val sslOut = sslSock.outputStream

                wsUpgrade(domain, path, sslOut, sslIn)
                RawWebSocket(sslIn, sslOut, underlyingSockets = listOf(sslSock, tcp))
            } catch (e: Exception) {
                try { tcp.close() } catch (_: Exception) {}
                throw e
            }
        }

        // ----------------------------------------------------------------
        // Shared WebSocket HTTP upgrade — sends request, validates 101
        // ----------------------------------------------------------------
        private fun wsUpgrade(domain: String, path: String, out: OutputStream, inp: InputStream) {
            val wsKey = Base64.getEncoder().encodeToString(ByteArray(16).also { RNG.nextBytes(it) })
            val req = buildString {
                append("GET $path HTTP/1.1\r\n")
                append("Host: $domain\r\n")
                append("Connection: Upgrade\r\n")
                append("Upgrade: websocket\r\n")
                append("Sec-WebSocket-Key: $wsKey\r\n")
                append("Sec-WebSocket-Version: 13\r\n")
                append("Sec-WebSocket-Protocol: binary\r\n")
                append("Origin: https://web.telegram.org\r\n")
                append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n")
                append("Accept-Language: en-US,en;q=0.9\r\n")
                append("Cache-Control: no-cache\r\n")
                append("Pragma: no-cache\r\n")
                append("\r\n")
            }
            Log.d(TAG, "WS upgrade → $domain: GET $path, host=$domain")
            Log.d(TAG, "WS req headers:\n${req.replace("\r\n", " | ").take(300)}")
            out.write(req.toByteArray())
            out.flush()

            // Read HTTP response headers
            val lines = mutableListOf<String>()
            val lineBuf = StringBuilder()
            var prev = -1
            var totalRead = 0
            while (totalRead < 8192) {
                val b = inp.read()
                if (b == -1) break
                totalRead++
                if (totalRead == 1) Log.d(TAG, "WS response first byte: 0x%02x".format(b))
                if (prev == '\r'.code && b == '\n'.code) {
                    val line = lineBuf.toString().trimEnd('\r')
                    if (line.isEmpty()) break
                    lines.add(line)
                    lineBuf.clear()
                } else {
                    lineBuf.append(b.toChar())
                }
                prev = b
            }
            if (lines.isEmpty()) throw WsHandshakeError(0, "empty response")

            val statusLine = lines[0]
            val statusCode = statusLine.split(" ", limit = 3).getOrNull(1)?.toIntOrNull() ?: 0
            if (statusCode == 101) {
                Log.i(TAG, "WS 101 OK → $domain | ${lines.drop(1).take(5).joinToString(" | ")}")
                return
            }

            // Non-101 — parse headers, log body, throw
            val hdrs = mutableMapOf<String, String>()
            lines.drop(1).forEach { line ->
                val idx = line.indexOf(':')
                if (idx > 0) hdrs[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
            }
            Log.w(TAG, "WS $domain: $statusLine | ${hdrs.entries.take(5).joinToString(", ") { "${it.key}: ${it.value}" }}")
            try {
                val bodyBuf = ByteArray(512)
                var bodyLen = 0
                while (bodyLen < bodyBuf.size) {
                    val b = inp.read(); if (b == -1) break
                    bodyBuf[bodyLen++] = b.toByte()
                }
                if (bodyLen > 0) Log.w(TAG, "WS $statusCode body: ${String(bodyBuf, 0, bodyLen, Charsets.UTF_8).take(300)}")
            } catch (_: Exception) {}
            throw WsHandshakeError(statusCode, statusLine, hdrs, hdrs["location"])
        }

        // ----------------------------------------------------------------
        // SSLSocket-based connect (no TLS fragmentation — used for Wi-Fi)
        // ----------------------------------------------------------------
        private suspend fun connectSslSocket(
            ip: String,
            domain: String,
            path: String,
            timeoutMs: Int
        ): RawWebSocket = withContext(Dispatchers.IO) {
            val factory = SSL_CTX.socketFactory
            val sock = factory.createSocket() as javax.net.ssl.SSLSocket
            try {
                sock.soTimeout = timeoutMs
                sock.tcpNoDelay = true
                sock.connect(InetSocketAddress(ip, 443), timeoutMs)
                val params = sock.sslParameters
                params.serverNames = listOf(javax.net.ssl.SNIHostName(domain))
                sock.sslParameters = params
                sock.startHandshake()
                Log.i(TAG, "TLS ok (SSLSocket): ${sock.session.protocol} / ${sock.session.cipherSuite} sni=$domain")

                val out = sock.outputStream
                val inp = sock.inputStream
                wsUpgrade(domain, path, out, inp)
                RawWebSocket(inp, out, underlyingSockets = listOf(sock))
            } catch (e: Exception) {
                try { sock.close() } catch (_: Exception) {}
                throw e
            }
        }

        fun xorMask(data: ByteArray, mask: ByteArray): ByteArray {
            val result = ByteArray(data.size)
            for (i in data.indices) result[i] = (data[i].toInt() xor mask[i % 4].toInt()).toByte()
            return result
        }

        fun buildFrame(opcode: Int, data: ByteArray, mask: Boolean = false): ByteArray {
            val header = mutableListOf<Byte>()
            header.add((0x80 or opcode).toByte())
            val length = data.size
            val maskBit = if (mask) 0x80 else 0x00
            when {
                length < 126 -> header.add((maskBit or length).toByte())
                length < 65536 -> {
                    header.add((maskBit or 126).toByte())
                    header.add((length shr 8).toByte())
                    header.add(length.toByte())
                }
                else -> {
                    header.add((maskBit or 127).toByte())
                    val bb = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                    bb.putLong(length.toLong())
                    bb.array().forEach { header.add(it) }
                }
            }
            return if (mask) {
                val maskKey = ByteArray(4).also { RNG.nextBytes(it) }
                maskKey.forEach { header.add(it) }
                header.toByteArray() + xorMask(data, maskKey)
            } else {
                header.toByteArray() + data
            }
        }
    }

    suspend fun send(data: ByteArray) = withContext(Dispatchers.IO) {
        if (closed) throw Exception("WebSocket closed")
        output.write(buildFrame(OP_BINARY, data, mask = true))
        output.flush()
    }

    suspend fun sendBatch(parts: List<ByteArray>) = withContext(Dispatchers.IO) {
        if (closed) throw Exception("WebSocket closed")
        val combined = parts.map { buildFrame(OP_BINARY, it, mask = true) }
            .reduce { a, b -> a + b }
        output.write(combined)
        output.flush()
    }

    // Keepalive ping — вызывается из WsPool пока соединение в ожидании
    suspend fun sendPing() = withContext(Dispatchers.IO) {
        if (closed) throw Exception("WebSocket closed")
        output.write(buildFrame(OP_PING, ByteArray(0), mask = true))
        output.flush()
    }

    suspend fun recv(): ByteArray? = withContext(Dispatchers.IO) {
        while (!closed) {
            val (opcode, payload) = readFrame()
            when (opcode) {
                OP_CLOSE -> {
                    closed = true
                    closeInitiator = "REMOTE"
                    if (payload.size >= 2) {
                        lastCloseCode = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
                        if (payload.size > 2) {
                            lastCloseReason = String(payload, 2, payload.size - 2, Charsets.UTF_8)
                        }
                    }
                    Log.i("ProxyDIAG", "WS_CLOSE     code=$lastCloseCode reason=${lastCloseReason ?: "n/a"} initiator=REMOTE")
                    try {
                        val reply = buildFrame(OP_CLOSE, if (payload.size >= 2) payload.copyOf(2) else ByteArray(0), mask = true)
                        output.write(reply); output.flush()
                    } catch (_: Exception) {}
                    return@withContext null
                }
                OP_PING -> {
                    try { output.write(buildFrame(OP_PONG, payload, mask = true)); output.flush() } catch (_: Exception) {}
                }
                OP_PONG -> {}
                OP_TEXT, OP_BINARY -> return@withContext payload
            }
        }
        null
    }

    suspend fun close() = withContext(Dispatchers.IO) {
        if (closed) return@withContext
        closed = true
        if (closeInitiator == null) closeInitiator = "LOCAL"
        Log.i("ProxyDIAG", "WS_CLOSE     code=$lastCloseCode reason=${lastCloseReason ?: "n/a"} initiator=$closeInitiator")
        try { output.write(buildFrame(OP_CLOSE, ByteArray(0), mask = true)); output.flush() } catch (_: Exception) {}
        try { output.close() } catch (_: Exception) {}
        try { input.close() } catch (_: Exception) {}
        underlyingSockets.forEach { try { it.close() } catch (_: Exception) {} }
    }

    private fun readFrame(): Pair<Int, ByteArray> {
        try {
            val hdr = ByteArray(2).also { readExactly(it) }
            val opcode = hdr[0].toInt() and 0x0F
            val isMasked = (hdr[1].toInt() and 0x80) != 0
            var length = (hdr[1].toInt() and 0x7F).toLong()
            length = when (length.toInt()) {
                126 -> { val b = ByteArray(2).also { readExactly(it) }; ((b[0].toInt() and 0xFF) shl 8 or (b[1].toInt() and 0xFF)).toLong() }
                127 -> { val b = ByteArray(8).also { readExactly(it) }; ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN).long }
                else -> length
            }
            if (length > 16 * 1024 * 1024) throw Exception("WS frame too large: $length bytes")
            val payload = if (isMasked) {
                val maskKey = ByteArray(4).also { readExactly(it) }
                val data = ByteArray(length.toInt()).also { readExactly(it) }
                xorMask(data, maskKey)
            } else {
                ByteArray(length.toInt()).also { readExactly(it) }
            }
            return Pair(opcode, payload)
        } catch (e: Exception) {
            // TCP closed without WS close frame → network/NAT kill
            if (closeInitiator == null) {
                closeInitiator = "ERROR"
                lastCloseReason = e.javaClass.simpleName + ": " + (e.message?.take(80) ?: "")
            }
            closed = true
            throw e
        }
    }

    private fun readExactly(buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = input.read(buf, offset, buf.size - offset)
            if (n == -1) throw Exception("Connection closed")
            offset += n
        }
    }
}