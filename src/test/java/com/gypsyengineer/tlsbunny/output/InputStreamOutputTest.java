package com.gypsyengineer.tlsbunny.output;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class InputStreamOutputTest {

    @Test
    public void indent() {
        InputStreamOutput iso = new InputStreamOutput();
        iso.info("test");
        assertEquals(1, iso.lines().size());
        assertTrue(iso.contains("test"));
        assertEquals("test", iso.lines().get(0).value());

        iso.increaseIndent();
        iso.info("holy cow");
        assertEquals(2, iso.lines().size());
        assertEquals("holy cow", iso.lines().get(1).value());
        assertTrue(iso.contains("holy"));
        assertTrue(iso.contains("cow"));
        assertFalse(iso.contains("    holy"));

        iso.decreaseIndent();
        iso.info("das ist %s", "gut");
        assertEquals(3, iso.lines().size());
        assertEquals("das ist gut", iso.lines().get(2).value());
        assertTrue(iso.contains("das"));
        assertTrue(iso.contains("gut"));
        assertTrue(iso.contains(" ist "));
    }

    @Test
    public void throwableInfo() {
        InputStreamOutput iso = new InputStreamOutput();
        iso.info("exception", new IOException("i/o error"));
        assertTrue(iso.contains("exception"));
        assertTrue(iso.contains("i/o error"));
        assertTrue(iso.contains("IOException"));
        assertTrue(iso.lines().size() > 0);
        assertEquals(Level.info, iso.lines().get(0).level());
    }

    @Test
    public void throwableAchtung() {
        InputStreamOutput iso = new InputStreamOutput();
        iso.achtung("exception", new IOException("i/o error"));
        assertTrue(iso.contains("exception"));
        assertTrue(iso.contains("i/o error"));
        assertTrue(iso.contains("IOException"));
        assertTrue(iso.lines().size() > 0);
        assertEquals(Level.achtung, iso.lines().get(0).level());
    }

    @Test
    public void important() {
        InputStreamOutput iso = new InputStreamOutput();
        iso.important("das is %s", "wichtig");
        assertEquals(1, iso.lines().size());
        assertEquals(Level.important, iso.lines().get(0).level());
        assertEquals("das is wichtig", iso.lines().get(0).value());
        assertTrue(iso.contains("wichtig"));
    }

    @Test
    public void addOutputWithLevel() {
        Output output = Output.local();
        output.info("info");
        output.important("important");
        output.achtung("oops");
        assertEquals(3, output.lines().size());
        assertEquals(Level.info, output.lines().get(0).level());
        assertEquals(Level.important, output.lines().get(1).level());
        assertEquals(Level.achtung, output.lines().get(2).level());

        InputStreamOutput iso = new InputStreamOutput();
        iso.add(output, Level.achtung);
        assertEquals(3, iso.lines().size());
        assertEquals(Level.achtung, iso.lines().get(0).level());
        assertEquals(Level.achtung, iso.lines().get(1).level());
        assertEquals(Level.achtung, iso.lines().get(2).level());
        assertEquals("info", iso.lines().get(0).value());
        assertEquals("important", iso.lines().get(1).value());
        assertEquals("achtung: oops", iso.lines().get(2).value());
    }
}
