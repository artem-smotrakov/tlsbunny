package com.gypsyengineer.tlsbunny.utils;

import org.junit.Test;

import static org.junit.Assert.*;

public class HexDumpTest {

    @Test
    public void printHex() {
        String text = HexDump.printHex(new byte[] {0, 1, 2, 3});
        System.out.println(text);
        assertEquals("0000:  00 01 02 03", text);
    }

    @Test
    public void printHexDiffSameArrays() {
        byte[] array = { 0, 1, 2, 4 };
        byte[] original = { 0, 1, 2, 4 };
        String text = HexDump.printHexDiff(array, original);
        System.out.println(text);
        assertEquals(HexDump.printHex(original), text);
    }

    @Test
    public void printHexDiff() {
        byte[] array = { 0, 1, 2, 3 };
        byte[] original = { 0, 1, 2, 4 };
        String text = HexDump.printHexDiff(array, original);
        System.out.println(text);
        assertEquals("0000:  00 01 02 [03]", text);

        array = new byte[] { 0, 1, 16, 4 };
        original = new byte[] { 0, 1, 2, 4 };
        text = HexDump.printHexDiff(array, original);
        System.out.println(text);
        assertEquals("0000:  00 01 [10] 04", text);

        array = new byte[] { (byte) 255, 1, 16, 4 };
        original = new byte[] { 0, 1, 16, 4 };
        text = HexDump.printHexDiff(array, original);
        System.out.println(text);
        assertEquals("0000:  [ff] 01 10 04", text);

        array = new byte[] { (byte) 255, 1, 32, 4 };
        original = new byte[] { 0, 1, 16, 4 };
        text = HexDump.printHexDiff(array, original);
        System.out.println(text);
        assertEquals("0000:  [ff] 01 [20] 04", text);
    }

    @Test
    public void explainSame() {
        byte[] array = { 0, 1, 2, 3 };
        byte[] original = { 0, 1, 2, 3 };
        String text = HexDump.explain("test", array, original);
        System.out.println(text);
        assertTrue(text.contains("0000:  00 01 02 03"));
        assertNotEquals(
                text.indexOf("0000:  00 01 02 03"),
                text.lastIndexOf("0000:  00 01 02 03"));
        assertTrue(text.contains("test (original):"));
        assertTrue(text.contains("test (modified):"));
        assertTrue(text.contains("nothing actually modified"));
    }

    @Test
    public void explain() {
        byte[] array = {32, 1, (byte) 255, 3};
        byte[] original = {0, 1, 2, 3};
        String text = HexDump.explain("test", array, original);
        System.out.println(text);
        assertTrue(text.contains("0000:  [20] 01 [ff] 03"));
        assertTrue(text.contains("0000:  [00] 01 [02] 03"));
        assertTrue(text.contains("test (original):"));
        assertTrue(text.contains("test (modified):"));
        assertFalse(text.contains("nothing actually modified"));
    }
}