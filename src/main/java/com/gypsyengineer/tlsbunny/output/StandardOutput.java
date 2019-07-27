package com.gypsyengineer.tlsbunny.output;

import java.util.List;

public class StandardOutput extends OutputWrapper {

    private static Level globalLevel = Level.valueOf(
            System.getProperty("tlsbunny.output.standard.level",
                    Level.info.name()));

    private static final Object consoleLock = new Object();

    private static final String ansi_red = "\u001B[31m";
    private static final String ansi_reset = "\u001B[0m";
    private static final boolean enableHighlighting = Boolean.parseBoolean(
            System.getProperty("tlsbunny.output.enable.highlighting", "true"));

    protected int index = 0;

    StandardOutput(Output output) {
        super(output, globalLevel);
    }

    @Override
    public void flush() {
        synchronized (consoleLock) {
            output.flush();

            List<Line> lines = output.lines();
            for (;index < lines.size(); index++) {
                Line line = lines.get(index);

                if (!line.has(minLevel)) {
                    continue;
                }

                String string = line.value();

                boolean isAchtung = line.level() == Level.achtung || string.contains("achtung");
                if (enableHighlighting && isAchtung) {
                    string = String.format("%s%s%s", ansi_red, string, ansi_reset);
                }

                System.out.println(string);
            }
        }
    }

    @Override
    public void clear() {
        super.clear();
        index = 0;
    }
}
