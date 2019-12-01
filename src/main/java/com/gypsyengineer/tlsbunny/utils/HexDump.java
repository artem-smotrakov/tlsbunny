package com.gypsyengineer.tlsbunny.utils;

import java.util.Arrays;

public class HexDump {

    public static final int width = 16;

    private static final String ansi_red = "\u001B[31m";
    private static final String ansi_reset = "\u001B[0m";

    private static final String leftHighlighter;
    private static final String rightHighlighter;
    static {
        boolean enableDiffHighlighting = Boolean.parseBoolean(
                System.getProperty("tlsbunny.output.enable.highlighting", "false"));
        if (enableDiffHighlighting) {
            leftHighlighter = ansi_red;
            rightHighlighter = ansi_reset;
        } else {
            leftHighlighter = "[";
            rightHighlighter = "]";
        }
    }

    public static String printHex(byte[] array) {
        return printHex(array, 0, array.length);
    }

    public static String printHex(byte[] array, int offset, int length) {
        StringBuilder builder = new StringBuilder();

        for (int rowOffset = offset; rowOffset < offset + length; rowOffset += width) {
            builder.append(String.format("%04x:  ", rowOffset));

            for (int index = 0; index < width; index++) {
                int k = rowOffset + index;
                if (k < array.length) {
                    builder.append(String.format("%02x ", array[k]));
                } else {
                    builder.append("   ");
                }
            }

            builder.append(String.format("%n"));
        }

        return builder.toString().trim();
    }

    public static String printHexDiff(byte[] array, byte[] original) {
        return printHexDiff(array, original, 0, array.length);
    }

    public static String printHexDiff(byte[] array, byte[] original, int offset, int length) {
        StringBuilder builder = new StringBuilder();

        for (int rowOffset = offset; rowOffset < offset + length; rowOffset += width) {
            builder.append(String.format("%04x:  ", rowOffset));

            for (int index = 0; index < width; index++) {
                int k = rowOffset + index;
                if (k < array.length) {
                    if (k >= original.length || array[k] != original[k]) {
                        builder.append(String.format("%s%02x%s ", leftHighlighter, array[k], rightHighlighter));
                    } else {
                        builder.append(String.format("%02x ", array[k]));
                    }
                } else {
                    builder.append("   ");
                }
            }
            if (rowOffset + width < offset + length) {
                builder.append("\n");
            }
        }

        return builder.toString().trim();
    }

    public static String explain(String what, byte[] encoding, byte[] fuzzed) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s (original):%n%s%n", what, printHexDiff(encoding, fuzzed)));
        sb.append(String.format("%s (modified):%n%s%n", what, printHexDiff(fuzzed, encoding)));
        if (Arrays.equals(encoding, fuzzed)) {
            sb.append("nothing actually modified");
        }

        return sb.toString().trim();
    }

}
