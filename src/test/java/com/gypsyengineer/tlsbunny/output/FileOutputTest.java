package com.gypsyengineer.tlsbunny.output;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

public class FileOutputTest {

    @Test
    public void main() throws IOException {
        Path path = Files.createTempFile(
                "tlsbunny", "file_output_test");
        try (Output output = new FileOutput(new LocalOutput(), path.toString())) {
            output.prefix("test");
            output.achtung("foo");
            output.increaseIndent();
            output.info("bar");
            output.important("important");
            output.decreaseIndent();;
            output.info("test");
            output.achtung("bar");
            output.flush();

            String[] expected = {
                    "[test] achtung: foo",
                    "[test]     important",
                    "[test] achtung: bar"
            };

            String[] lines = Files.readAllLines(path).toArray(new String[0]);
            assertArrayEquals(expected, lines);
            assertTrue(output.contains("foo"));

            output.clear();
            assertEquals(0, output.lines().size());
            assertFalse(output.contains("foo"));
            assertFalse(output.contains("bar"));
            assertFalse(output.contains("important"));
        } finally {
            Files.delete(path);
        }
    }

    @Test
    public void exception() throws IOException {
        Path path = Files.createTempFile(
                "tlsbunny", "file_output_test");
        try (Output output = new FileOutput(new LocalOutput(), path.toString())) {
            output.prefix("test");
            output.info("error", new IOException("oops"));
            output.flush();

            assertTrue(output.contains("[test] java.io.IOException: oops"));
        } finally {
            Files.delete(path);
        }
    }

    @Test
    public void listener() throws IOException {
        Path path = Files.createTempFile(
                "tlsbunny", "file_output_test");
        try (Output output = new FileOutput(new LocalOutput(), path.toString())) {

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
        } finally {
            Files.delete(path);
        }
    }
}
