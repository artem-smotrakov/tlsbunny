package com.gypsyengineer.tlsbunny;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;

public class JSSEUtils {

    public static void setKeyStores() {
        System.setProperty("javax.net.ssl.keyStore", "certs/keystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");
    }

    public static boolean supportsTls13() {
        try {
            SSLContext.getInstance("TLSv1.3");
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
        return true;
    }
}
