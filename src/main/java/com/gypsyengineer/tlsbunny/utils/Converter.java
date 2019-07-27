package com.gypsyengineer.tlsbunny.utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Converter {
    
    private static final int INTEGER_ENCODING_LENGTH = 4; 
    private static final int LONG_ENCODING_LENGTH = 8; 

    public static BigInteger hex2int(String hex) {
        return new BigInteger(hex, 16);
    }

    public static byte[] hex2bytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        int length = hex.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) 
                    + Character.digit(hex.charAt(i+1), 16));
        }

        return bytes;
    }
    
    public static int bytes2int(byte[] bytes) {
        //int n = 0;
        //for (int i = 0; i < bytes.length; i++) {
        //    n |= (bytes[i] & 0xFF) << (8 * (bytes.length - i - 1));
        //}
        //return n;
        return ByteBuffer.wrap(leftPadding(bytes, INTEGER_ENCODING_LENGTH)).getInt();
    }

    public static byte[] int2bytes(int n, int length) {
        byte[] encoding = int2bytes(n);
        if (encoding.length < length) {
            return leftPadding(encoding, length);
        }

        if (encoding.length > length) {
            return trimLeft(encoding, length);
        }

        return encoding;
    }

    public static byte[] int2bytes(int n) {
        return ByteBuffer.allocate(INTEGER_ENCODING_LENGTH).putInt(n).array();
    }

    public static byte[] long2bytes(long n, int length) {
        byte[] encoding = long2bytes(n);
        if (encoding.length < length) {
            return leftPadding(encoding, length);
        }

        if (encoding.length > length) {
            return trimLeft(encoding, length);
        }

        return encoding;
    }

    public static byte[] long2bytes(long n) {
        return ByteBuffer.allocate(LONG_ENCODING_LENGTH).putLong(n).array();
    }
    
    public static byte[] trimLeft(byte[] bytes, int length) {
        return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
    }

    public static byte[] leftPadding(byte[] bytes, int length) {
        if (length <= bytes.length) {
            return bytes;
        }
        
        byte[] array = new byte[length];
        System.arraycopy(bytes, 0, array, length - bytes.length, bytes.length);
        return array;
    }

    public static byte[] rightPadding(byte[] bytes, int length) {
        if (length <= bytes.length) {
            return bytes;
        }

        byte[] array = new byte[length];
        System.arraycopy(bytes, 0, array, 0, bytes.length);
        return array;
    }
}
