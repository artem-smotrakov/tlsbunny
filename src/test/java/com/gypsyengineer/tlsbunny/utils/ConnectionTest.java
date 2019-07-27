package com.gypsyengineer.tlsbunny.utils;


import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import java.io.IOException;
import java.net.ServerSocket;

import static org.junit.Assert.*;

public class ConnectionTest {

    private static final long delay = 1000; // in millis
    private static final byte[] message =
            "like most of life's problems, this one can be solved with bending"
                    .getBytes();

    @Test
    public void basic() throws Exception {
        try (EchoServer server = new EchoServer()) {
            new Thread(server).start();
            Thread.sleep(delay);

            Connection connection = Connection.create("localhost", server.port());

            connection.send(message);
            byte[] data = connection.read();
            assertArrayEquals(message, data);

            connection = Connection.create("localhost", server.port());
            connection.send(CipherSuite.TLS_AES_128_GCM_SHA256);
            data = connection.read();
            CipherSuite suite = StructFactory.getDefault().parser().parseCipherSuite(data);
            assertEquals(suite, CipherSuite.TLS_AES_128_GCM_SHA256);

            assertNull(connection.exception());
        }
    }

    private static class EchoServer implements Runnable, AutoCloseable {

        private static final int free_port = 0;

        private final ServerSocket serverSocket;

        public EchoServer() throws IOException {
            this(free_port);
        }

        public EchoServer(int port) throws IOException {
            this(new ServerSocket(port));
        }

        private EchoServer(ServerSocket ssocket) {
            this.serverSocket = ssocket;
        }

        public int port() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void run() {
            while (true) {
                try (Connection connection = Connection.create(serverSocket.accept())) {
                    byte[] data = connection.read();
                    connection.send(data);
                } catch (Exception e) {
                    break;
                }
            }
        }

        @Override
        public void close() throws IOException {
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
        }
    }
}
