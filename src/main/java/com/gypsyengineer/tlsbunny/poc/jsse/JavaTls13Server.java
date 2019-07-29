package com.gypsyengineer.tlsbunny.poc.jsse;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;

public class JavaTls13Server {

    private static final int port = 50101;
    private static final String[] protocols = { "TLSv1.3" };
    private static final String[] cipher_suites = { "TLS_AES_128_GCM_SHA256" };
    private static final String message =
            "Like most of life's problems, this one can be solved with bending!";
    private static final byte[] http_response = String.format(
            "HTTP/1.1 200 OK\n" +
            "Content-Length: %d\n" +
            "Content-Type: text/html\n" +
            "Connection: Closed\n\n%s", message.length(), message).getBytes();

    public static void main(String[] args) throws Exception {
        if (System.getProperty("javax.net.ssl.keyStore") == null) {
            System.setProperty("javax.net.ssl.keyStore", "certs/keystore");
        }
        if (System.getProperty("javax.net.ssl.keyStorePassword") == null) {
            System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");
        }

        try (HttpsServer server = HttpsServer.create(port)) {
            server.run();
        }
    }

    public static class HttpsServer implements Runnable, AutoCloseable {

        private static final int free_port = 0;

        private final SSLServerSocket sslServerSocket;

        private HttpsServer(SSLServerSocket sslServerSocket) {
            this.sslServerSocket = sslServerSocket;
        }

        public int port() {
            return sslServerSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            if (sslServerSocket != null && !sslServerSocket.isClosed()) {
                sslServerSocket.close();
            }
        }

        @Override
        public void run() {
            System.out.printf("server started on port %d%n", port());

            while (true) {
                try (SSLSocket socket = (SSLSocket) sslServerSocket.accept()) {
                    System.out.println("accepted");
                    InputStream is = new BufferedInputStream(socket.getInputStream());
                    OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                    byte[] data = new byte[2048];
                    int len = is.read(data);
                    if (len <= 0) {
                        throw new IOException("no data received");
                    }
                    System.out.printf("server received %d bytes: %s%n",
                            len, new String(data, 0, len));
                    os.write(http_response, 0, len);
                    os.flush();
                } catch (SSLException e) {
                    System.out.printf("ssl exception: %s%n", e.getMessage());
                    System.out.println("continue");
                } catch (IOException e) {
                    System.out.println("i/o exception, stop");
                    e.printStackTrace(System.out);
                    break;
                }
            }
        }

        public static HttpsServer create() throws IOException {
            return create(free_port);
        }

        public static HttpsServer create(int port) throws IOException {
            SSLServerSocket socket = (SSLServerSocket)
                    SSLServerSocketFactory.getDefault().createServerSocket(port);
            socket.setEnabledProtocols(protocols);
            socket.setEnabledCipherSuites(cipher_suites);
            return new HttpsServer(socket);
        }
    }
}