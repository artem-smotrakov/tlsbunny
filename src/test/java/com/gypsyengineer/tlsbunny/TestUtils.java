package com.gypsyengineer.tlsbunny;

import com.gypsyengineer.tlsbunny.fuzzer.AbstractFlipFuzzer;
import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.utils.WhatTheHell;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestUtils {

    public interface TestAction {
        void run() throws Exception;
    }

    public static Path createTempDirectory() throws IOException {
        Path dir = Files.createTempDirectory("tlsbunny_test");
        assertTrue(Files.exists(dir));
        assertTrue(Files.isDirectory(dir));

        return dir;
    }

    public static List<String> findFiles(Path dir, String prefix) throws IOException {
        try (Stream<Path> walk = Files.walk(dir)) {
            return walk.map(Path::toFile)
                    .filter(f -> f.getName().startsWith(prefix))
                    .map(File::toString)
                    .collect(Collectors.toList());
        }
    }

    public static boolean searchInFile(String filename, String string) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(filename));
        for (String line : lines) {
            if (line.contains(string)) {
                return true;
            }
        }

        return false;
    }

    public static void removeDirectory(Path path) throws IOException {
        Files.walk(path)
                .filter(Files::isRegularFile)
                .map(Path::toFile)
                .forEach(File::delete);

        Files.delete(path);
    }

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
                t.printStackTrace();
                fail(String.format("expected {} but caught {}",
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
    public static void expectUnsupportedMethods(
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
                System.out.printf("call {}()%n", method.getName());
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
                if (e.getCause() instanceof UnsupportedOperationException == false) {
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

    public static class FakeFlipFuzzer extends AbstractFlipFuzzer implements FakeFuzzer {

        private int count = 0;

        @Override
        synchronized protected byte[] fuzzImpl(byte[] array) {
            // do nothing
            count++;
            return array;
        }

        @Override
        synchronized public int count() {
            return count;
        }
    }

    public static class FakeVectorFuzzer implements Fuzzer<Vector<Byte>>, FakeFuzzer {

        private int count = 0;
        private long test = 0;

        @Override
        public boolean canFuzz() {
            return true;
        }

        @Override
        synchronized public Vector fuzz(Vector object) {
            count++;
            return object;
        }

        @Override
        public void moveOn() {
            test++;
        }

        @Override
        public String state() {
            return String.valueOf(test);
        }

        @Override
        public void state(String string) {
            test = Integer.parseInt(string);
        }

        @Override
        synchronized public int count() {
            return count;
        }
    }

    public static class FakeCompressionMethodFuzzer
            implements Fuzzer<Vector<CompressionMethod>>, FakeFuzzer {

        private int count = 0;
        private long test = 0;

        @Override
        public boolean canFuzz() {
            return true;
        }

        @Override
        synchronized public Vector<CompressionMethod> fuzz(Vector<CompressionMethod> object) {
            count++;
            return object;
        }

        @Override
        public void moveOn() {
            test++;
        }

        @Override
        public String state() {
            return String.valueOf(test);
        }

        @Override
        public void state(String string) {
            test = Integer.parseInt(string);
        }

        @Override
        synchronized public int count() {
            return count;
        }
    }

    public static class FakeCipherSuitesFuzzer
            implements Fuzzer<Vector<CipherSuite>>, FakeFuzzer {

        private int count = 0;
        private long test = 0;

        @Override
        public boolean canFuzz() {
            return true;
        }

        @Override
        synchronized public Vector<CipherSuite> fuzz(Vector<CipherSuite> object) {
            count++;
            return object;
        }

        @Override
        public void moveOn() {
            test++;
        }

        @Override
        public String state() {
            return String.valueOf(test);
        }

        @Override
        public void state(String string) {
            test = Integer.parseInt(string);
        }

        @Override
        synchronized public int count() {
            return count;
        }
    }

    public static class FakeExtensionVectorFuzzer
            implements Fuzzer<Vector<Extension>>, FakeFuzzer {

        private int count = 0;
        private long test = 0;

        @Override
        public boolean canFuzz() {
            return true;
        }

        @Override
        synchronized public Vector<Extension> fuzz(Vector<Extension> object) {
            count++;
            return object;
        }

        @Override
        public void moveOn() {
            test++;
        }

        @Override
        public String state() {
            return String.valueOf(test);
        }

        @Override
        public void state(String string) {
            test = Integer.parseInt(string);
        }

        @Override
        synchronized public int count() {
            return count;
        }
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
        synchronized public int count() {
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
