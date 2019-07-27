package com.gypsyengineer.tlsbunny.output;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class OutputWrapperTest {

    private static final Line null_line = null;
    private static final OutputListener null_listener = null;
    private static final Output null_output = null;

    @Test
    public void main() {
        CounterOutput checker = new CounterOutput();
        try (TestWrapperOutput wrapper = new TestWrapperOutput(checker)) {
            wrapper.add(null_line);
            wrapper.add(null_listener);
            wrapper.add(null_output);
            wrapper.add(Output.local(), Level.achtung);
            wrapper.increaseIndent();
            wrapper.decreaseIndent();
            wrapper.prefix("test");
            wrapper.info("%s%n", "foo");
            wrapper.info("error", new RuntimeException("oops"));
            wrapper.achtung("%s%n", "foo");
            wrapper.achtung("error", new RuntimeException("oops"));
            wrapper.important("%s%n", "foo");
            wrapper.important("error", new RuntimeException("oops"));
            wrapper.lines();
            wrapper.contains("oops");
            wrapper.flush();
            wrapper.clear();
        }

        assertEquals(18, checker.counter);
    }

    private static class TestWrapperOutput extends OutputWrapper {

        TestWrapperOutput(Output output) {
            super(output);
        }
    }

    private static class CounterOutput implements Output {

        int counter = 0;

        @Override
        public Output add(OutputListener listener) {
            counter++;
            return this;
        }

        @Override
        public void increaseIndent() {
            counter++;
        }

        @Override
        public void decreaseIndent() {
            counter++;
        }

        @Override
        public void prefix(String prefix) {
            counter++;
        }

        @Override
        public void info(String format, Object... values) {
            counter++;
        }

        @Override
        public void info(String message, Throwable e) {
            counter++;
        }

        @Override
        public void important(String format, Object... values) {
            counter++;
        }

        @Override
        public void important(String message, Throwable e) {
            counter++;
        }

        @Override
        public void achtung(String format, Object... values) {
            counter++;
        }

        @Override
        public void achtung(String message, Throwable e) {
            counter++;
        }

        @Override
        public void add(Line line) {
            counter++;
        }

        @Override
        public void add(Output output) {
            counter++;
        }

        @Override
        public List<Line> lines() {
            counter++;
            return Collections.emptyList();
        }

        @Override
        public void add(Output output, Level level) {
            counter++;
        }

        @Override
        public boolean contains(String line) {
            counter++;
            return false;
        }

        @Override
        public void clear() {
            counter++;
        }

        @Override
        public void flush() {
            counter++;
        }

        @Override
        public void close() {
            counter++;
        }
    }
}
