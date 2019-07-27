package com.gypsyengineer.tlsbunny.output;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.List;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class FileOutput extends OutputWrapper {

    private static Level globalLevel = Level.valueOf(
            System.getProperty("tlsbunny.output.file.level",
                    Level.important.name()));
    static {
        System.out.printf("[output] tlsbunny.output.file.level = %s%n", globalLevel);
    }

    private final Writer writer;
    private int index = 0;

    FileOutput(Output output, String filename) {
        super(output, globalLevel);

        try {
            writer = new BufferedWriter(new FileWriter(filename));
        } catch (IOException e) {
            throw whatTheHell("could not create a file", e);
        }
    }

    @Override
    public void flush() {
        output.flush();

        try {
            List<Line> lines = output.lines();
            for (;index < lines.size(); index++) {
                Line line = lines.get(index);

                if (!line.has(minLevel)) {
                    continue;
                }

                writer.write(line.value());
                writer.write("\n");
            }
            writer.flush();
        } catch (IOException e) {
            throw whatTheHell("could not write to a file", e);
        }
    }

    @Override
    public void close() {
        flush();

        try {
            writer.close();
        } catch (IOException e) {
            throw whatTheHell("could not close file writer", e);
        }
    }

    @Override
    public void clear() {
        super.clear();
        index = 0;
    }
}
