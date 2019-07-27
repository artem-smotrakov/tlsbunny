package com.gypsyengineer.tlsbunny.utils;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ConverterTest {

    @Test
    public void int2bytes() {
        int2bytes(0);
        int2bytes(1);
        int2bytes(7);
        int2bytes(17);
        int2bytes(32);
        int2bytes(42);
        int2bytes(64);
        int2bytes(111);
        int2bytes(128);
        int2bytes(201);
        int2bytes(256);
        int2bytes(2222);
        int2bytes(33333);
        int2bytes(65000);
        int2bytes(65535);
        int2bytes(65536);
        int2bytes(80000);
        int2bytes(1000000);
    }

    private static void int2bytes(int n) {
        int m = Converter.bytes2int(Converter.int2bytes(n));
        assertEquals(n, m);
    }

}
