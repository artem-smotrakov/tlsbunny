package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;

import java.util.Objects;

public class CipherSuiteImpl implements CipherSuite {

    private final int first;
    private final int second;

    CipherSuiteImpl(int first, int second) {
        check(first);
        check(second);
        this.first = first;
        this.second = second;
    }

    @Override
    public int getFirst() {
        return first;
    }

    @Override
    public int getSecond() {
        return second;
    }

    @Override
    public AEAD.Method cipher() {
        if (first != 0x13) {
            return AEAD.Method.unknown;
        }
        
        switch (second) {
            case 0x01:
                return AEAD.Method.aes_128_gcm;
            case 0x02:
                return AEAD.Method.aes_256_gcm;
            case 0x03:
                return AEAD.Method.chacha20_poly1305;
            case 0x04:
                return AEAD.Method.aes_128_ccm;
            case 0x05:
                return AEAD.Method.aes_128_ccm_8;
            default:
                return AEAD.Method.unknown;
        }
    }
    
    @Override
    public int keyLength() {
        if (first != 0x13) {
            return 0;
        }
        
        switch (second) {
            case 0x01:
            case 0x04:
            case 0x05:
                return 16;
            case 0x02:
            case 0x03:
                return 32;
            default:
                return 0;
        }
    }
    
    @Override
    public int ivLength() {
        if (first != 0x13) {
            return 0;
        }
        
        switch (second) {
            case 0x01:
            case 0x04:
            case 0x05:
                return 12;
            case 0x02:
            case 0x03:
                // TODO: fix it
                throw new RuntimeException("I don't know!");
        }
        
        return 0;
    }
    
    @Override
    public String hash() {
        if (first != 0x13) {
            return unknown;
        }
        
        switch (second) {
            case 0x01:
            case 0x03:
            case 0x04:
            case 0x05:
                return "SHA-256";
            case 0x02:
                return "SHA-384";
            default:
                return unknown;
        }
    }
    
    @Override
    public int hashLength() {
        if (first != 0x13) {
            return 0;
        }
        
        switch (second) {
            case 0x01:
            case 0x03:
            case 0x04:
            case 0x05:
                return 32;
            case 0x02:
                return 48;
            default:
                return 0;
        }
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() {
        return new byte[] { (byte) first, (byte) second };
    }

    @Override
    public CipherSuiteImpl copy() {
        return new CipherSuiteImpl(first, second);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CipherSuiteImpl that = (CipherSuiteImpl) o;
        return first == that.first &&
                second == that.second;
    }

    @Override
    public int hashCode() {
        return Objects.hash(first, second);
    }

    private static void check(int value) {
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException();
        }
    }

}
