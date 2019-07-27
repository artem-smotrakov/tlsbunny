package com.gypsyengineer.tlsbunny.output;

import org.junit.Test;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.output.Level.achtung;
import static com.gypsyengineer.tlsbunny.output.Level.info;
import static org.junit.Assert.*;

public class LocalOutputTest {

    @Test
    public void main() {
        try (Output output = new LocalOutput()) {
            output.prefix("test");
            output.achtung("foo");
            output.increaseIndent();
            output.info("bar");
            output.decreaseIndent();;
            output.info("test");
            output.flush();

            Line[] expected = {
                    new Line(achtung, "[test] achtung: foo"),
                    new Line(info, "[test]     bar"),
                    new Line(info, "[test] test")
            };

            Line[] lines = output.lines().toArray(new Line[0]);
            assertArrayEquals(expected, lines);
            assertTrue(output.contains("foo"));

            output.clear();
            assertEquals(0, output.lines().size());
            assertFalse(output.contains("foo"));
            assertFalse(output.contains("bar"));
            assertFalse(output.contains("test"));
        }
    }

    @Test
    public void exception() {
        try (Output output = new LocalOutput()) {
            output.prefix("test");
            output.info("error", new IOException("oops"));
            output.flush();

            assertTrue(output.contains("[test] java.io.IOException: oops"));
        }
    }

    @Test
    public void listener() {
        try (Output output = new LocalOutput()) {

            output.add(new OutputListener() {

                @Override
                public void receivedInfo(String... strings) {
                    assertNotNull(strings);
                    assertEquals(1, strings.length);
                    assertEquals("error", strings[0]);
                }

                @Override
                public void receivedImportant(String... strings) {
                    fail("should not be here!");
                }

                @Override
                public void receivedAchtung(String... strings) {
                    fail("should not be here!");
                }
            });

            output.prefix("test");
            output.info("error");
            output.flush();

            assertTrue(output.contains("[test] error"));
        }
    }
}
