package com.gypsyengineer.tlsbunny;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.util.Objects;

public class SimpleJSSEHttpsServer implements Runnable, AutoCloseable {

    private static final Logger logger = LogManager.getLogger(SimpleJSSEHttpsServer.class);
    private static final String[] protocols = { "TLSv1.3" };
    private static final String[] cipher_suites = { "TLS_AES_128_GCM_SHA256" };
    private static final String message =
            "Like most of life's problems, this one can be solved with bending!";
    private static final byte[] http_response = String.format(
            "HTTP/1.1 200 OK\n" +
            "Content-Length: %d\n" +
            "Content-Type: text/html\n" +
            "Connection: Closed\n\n%s", message.length(), message).getBytes();

    private static final int free_port = 0;
    private final SSLServerSocket sslServerSocket;
    private boolean started = false;
    private boolean shouldStop = false;

    private SimpleJSSEHttpsServer(SSLServerSocket sslServerSocket) {
        Objects.requireNonNull(sslServerSocket,
                "Hey! Server socket can't be null");
        this.sslServerSocket = sslServerSocket;
    }

    public int port() {
        return sslServerSocket.getLocalPort();
    }

    @Override
    public void close() {
        stop();
    }

    @Override
    public void run() {
        logger.info("server started on port {}", port());

        while (true) {
            synchronized (this) {
                started = true;
                if (shouldStop) {
                    break;
                }
            }
            try (SSLSocket socket = (SSLSocket) sslServerSocket.accept()) {
                logger.info("accepted");
                InputStream is = new BufferedInputStream(socket.getInputStream());
                OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len <= 0) {
                    throw new IOException("no data received");
                }
                logger.info("server received {} bytes: {}",
                        len, new String(data, 0, len));
                os.write(http_response, 0, len);
                os.flush();
            } catch (IOException e) {
                logger.warn("I/O exception, but continue", e);
            }
        }
    }

    public boolean started() {
        synchronized (this) {
            return started;
        }
    }

    public void stop() {
        synchronized (this) {
            shouldStop = true;
        }
        if (!sslServerSocket.isClosed()) {
            try {
                sslServerSocket.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    public static SimpleJSSEHttpsServer start() throws IOException {
        return start(free_port);
    }

    public static SimpleJSSEHttpsServer start(int port) throws IOException {
        SSLServerSocket socket = (SSLServerSocket)
                SSLServerSocketFactory.getDefault().createServerSocket(port);
        socket.setEnabledProtocols(protocols);
        socket.setEnabledCipherSuites(cipher_suites);
        SimpleJSSEHttpsServer server = new SimpleJSSEHttpsServer(socket);
        new Thread(server, SimpleJSSEHttpsServer.class.getSimpleName()).start();
        while (!server.started()) {
            TestUtils.sleep(1);
        }
        return server;
    }

}