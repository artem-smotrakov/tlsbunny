package com.gypsyengineer.tlsbunny;

import com.gypsyengineer.tlsbunny.fuzzer.AbstractFlipFuzzer;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.utils.WhatTheHell;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestUtils {

    public interface TestAction {
        void run() throws Exception;
    }

    public static void sleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @SafeVarargs
    public static <T> void assertContains(T object, T... array) {
        Objects.requireNonNull(object);
        Objects.requireNonNull(array);
        assertTrue(array.length > 0);
        for (Object element : array) {
            if (object.equals(element)) {
                return;
            }
        }

        fail("the list doesn't contain the object!");
    }

    public static void expectIllegalState(TestAction test) throws Exception {
        try {
            test.run();
            fail("expected an exception");
        } catch (IllegalStateException e) {
            // good
        }
    }

    public static void expectWhatTheHell(TestAction test) throws Exception {
        try {
            test.run();
            fail("expected an exception");
        } catch (WhatTheHell e) {
            // good
        }
    }

    public static void expectUnsupported(TestAction test) throws Exception {
        try {
            test.run();
            fail("expected an exception");
        } catch (UnsupportedOperationException e) {
            // good
        }
    }

    public static void expectException(TestAction test, Class expected) {
        Objects.requireNonNull(test, "no action!");
        Objects.requireNonNull(expected, "no class!");
        try {
            test.run();
            fail("expected an exception");
        } catch (Throwable t) {
            if (!t.getClass().equals(expected)) {
                t.printStackTrace(System.err);
                fail(String.format("expected %s but caught %s",
                        expected.getSimpleName(), t.getClass().getSimpleName()));
            }
        }
    }

    public static ClientHello createClientHello() {
        StructFactory factory = StructFactory.getDefault();
        return factory.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[32],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of(factory.createExtension(
                        ExtensionType.supported_versions,
                        new byte[64])));
    }

    public static Extension createExtension() {
        return StructFactory.getDefault().createExtension(
                ExtensionType.supported_versions, new byte[42]);
    }

    // check if methods without parameters throw UnsupportedOperationException
    // TODO: test all methods
    private static void expectUnsupportedMethods(
            Object object, List<String> excluded) throws Exception {

        for (Method method : object.getClass().getDeclaredMethods()) {
            if (method.getName().startsWith("$")) {
                continue;
            }

            if (method.isSynthetic()) {
                continue;
            }

            if (method.getParameterCount() > 0) {
                continue;
            }

            try {
                System.out.printf("call %s()%n", method.getName());
                method.invoke(object);
                if (excluded.contains(method.getName())) {
                    continue;
                }
                fail("expected UnsupportedOperationException");
            } catch (UnsupportedOperationException e) {
                if (!excluded.contains(method.getName())) {
                    fail("unexpected UnsupportedOperationException");
                }
            } catch (InvocationTargetException e) {
                if (!UnsupportedOperationException.class.equals(e.getCause().getClass())) {
                    fail("unexpected cause");
                }
            }
        }
    }

    public static void expectUnsupportedMethods(
            Object object, String... excluded) throws Exception {

        expectUnsupportedMethods(object, List.of(excluded));
    }

    public interface FakeFuzzer {
        int count();
    }

    // the fuzzer just sets all bytes of encoding to zeroes
    public static class ZeroFuzzer extends AbstractFlipFuzzer implements FakeFuzzer {

        private int count = 0;

        @Override
        synchronized protected byte[] fuzzImpl(byte[] array) {
            count++;
            return new byte[array.length];
        }

        @Override
        public synchronized int count() {
            return count;
        }

    }

    public static class FakeTestAnalyzer implements Analyzer {

        private final List<Engine> engines = new ArrayList<>();

        @Override
        public Analyzer add(Engine... engines) {
            this.engines.addAll(List.of(engines));
            return this;
        }

        @Override
        public Analyzer run() {
            return this;
        }

        @Override
        public Engine[] engines() {
            return engines.toArray(new Engine[0]);
        }
    }
}
