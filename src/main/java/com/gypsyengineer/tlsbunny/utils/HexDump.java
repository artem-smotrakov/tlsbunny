package com.gypsyengineer.tlsbunny.utils;

public class HexDump {

    public static final int width = 16;

    public static final String ansi_red ;
    public static final String ansi_reset;
    static {
        boolean enableDiffHighlighting = Boolean.valueOf(
                System.getProperty("tlsbunny.output.enable.highlighting", "true"));
        if (enableDiffHighlighting) {
            ansi_red = "\u001B[31m";
            ansi_reset = "\u001B[0m";
        } else {
            ansi_red = "";
            ansi_reset = "";
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

        return builder.toString();
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
                        builder.append(String.format("%s%02x%s ", ansi_red, array[k], ansi_reset));
                    } else {
                        builder.append(String.format("%02x ", array[k]));
                    }
                } else {
                    builder.append("   ");
                }
            }

            builder.append(String.format("%n"));
        }

        return builder.toString();
    }

}
