package com.gypsyengineer.tlsbunny;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.NoSuchAlgorithmException;

public class JSSEUtils {

    public static void setKeyStores() {
        System.setProperty("javax.net.ssl.keyStore", "certs/keystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");
    }

    public static void setTrustStores() {
        System.setProperty("javax.net.ssl.trustStore", "certs/keystore");
        System.setProperty("javax.net.ssl.trustStorePassword", "passphrase");
    }

    public static void enableSessionTicketExtension() {
        System.setProperty("jdk.tls.client.enableSessionTicketExtension", "true");
        System.setProperty("jdk.tls.server.enableSessionTicketExtension", "true");
    }

    public static boolean supportsTls13() {
        try {
            SSLContext.getInstance("TLSv1.3");
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
        return true;
    }

    public static SSLSession connectTo(int port) throws IOException {
        try (SSLSocket socket = createSocket("localhost", port)) {
            InputStream is = new BufferedInputStream(socket.getInputStream());
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());
            os.write("GET / HTTP/1.1\n\n".getBytes());
            os.flush();
            byte[] data = new byte[2048];
            int len = is.read(data);
            if (len <= 0) {
                throw new IOException("no data received");
            }
            System.out.printf("client received %d bytes: %s%n",
                    len, new String(data, 0, len));
            return socket.getSession();
        }
    }

    public static SSLSocket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault()
                .createSocket(host, port);
        socket.setEnabledProtocols( new String[] { "TLSv1.3" });
        socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
        return socket;
    }
}
