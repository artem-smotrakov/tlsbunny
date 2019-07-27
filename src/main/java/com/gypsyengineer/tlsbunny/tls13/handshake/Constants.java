package com.gypsyengineer.tlsbunny.tls13.handshake;

public class Constants {

    public static final byte[] zero_salt = new byte[0];
    public static final byte[] zero_hash_value = new byte[0];

    public static byte[] exp_master() {
        return "exp master".getBytes();
    }
    
    public static byte[] ext_binder() {
        return "ext binder".getBytes();
    }
    
    public static byte[] res_binder() {
        return "res binder".getBytes();
    }
    
    public static byte[] c_e_traffic() {
        return "c e traffic".getBytes();
    }
    
    public static byte[] e_exp_master() {
        return "e exp master".getBytes();
    }
    
    public static byte[] derived() {
        return "derived".getBytes();
    }
    
    public static byte[] c_hs_traffic() {
        return "c hs traffic".getBytes();
    }

    public static byte[] s_hs_traffic() {
        return "s hs traffic".getBytes();
    }

    public static byte[] c_ap_traffic() {
        return "c ap traffic".getBytes();
    }

    public static byte[] s_ap_traffic() {
        return "s ap traffic".getBytes();
    }

    public static byte[] res_master() {
        return "res master".getBytes();
    }

    public static byte[] key() {
        return "key".getBytes();
    }

    public static byte[] iv() {
        return "iv".getBytes();
    }

    public static byte[] finished() {
        return "finished".getBytes();
    }

}
