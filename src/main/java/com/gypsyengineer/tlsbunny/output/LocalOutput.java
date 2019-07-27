package com.gypsyengineer.tlsbunny.output;

import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.output.Level.achtung;
import static com.gypsyengineer.tlsbunny.output.Level.important;
import static com.gypsyengineer.tlsbunny.output.Level.info;

public class LocalOutput implements Output {

    private static final String default_prefix = "";
    private static final int indent_step = 4;

    private final List<Line> lines = new ArrayList<>();
    private String prefix = default_prefix;
    private String indent = "";
    private final List<OutputListener> listeners
            = Collections.synchronizedList(new ArrayList<>());

    LocalOutput() {

    }

    LocalOutput(String prefix) {
        prefix(prefix);
    }

    @Override
    synchronized public Output add(OutputListener listener) {
        listeners.add(listener);
        return this;
    }

    @Override
    synchronized public void increaseIndent() {
        int indentLength = indent.length() + indent_step;
        indent = new String(new char[indentLength]).replace('\0', ' ');
    }

    @Override
    synchronized public void decreaseIndent() {
        int indentLength = indent.length() - indent_step;

        if (indentLength < 0) {
            indentLength = 0;
        }

        indent = new String(new char[indentLength]).replace('\0', ' ');
    }

    synchronized private void printf(Level level, String format, Object... params) {
        lines.add(new Line(level, String.format(format, params)));
    }

    @Override
    synchronized public void prefix(String prefix) {
        Objects.requireNonNull(prefix, "prefix can't be null!");
        if (prefix.isEmpty()) {
            this.prefix = prefix;
        } else {
            this.prefix = String.format("[%s] ", prefix);
        }
    }

    @Override
    synchronized public void info(String format, Object... values) {
        String text = format;
        if (values != null && values.length != 0) {
            text = String.format(format, values);
        }

        String[] lines = text.split("\\r?\\n");

        for (OutputListener listener : listeners) {
            listener.receivedInfo(lines);
        }

        for (String line : lines) {
            printf(info,"%s%s%s", prefix, indent, line);
        }
    }

    @Override
    synchronized public void info(String message, Throwable e) {
        info(String.format("%s%n%s", message, Utils.toString(e)));
    }

    @Override
    public void important(String format, Object... values) {
        String text = format;
        if (values != null && values.length != 0) {
            text = String.format(format, values);
        }

        String[] lines = text.split("\\r?\\n");

        for (OutputListener listener : listeners) {
            listener.receivedImportant(lines);
        }

        for (String line : lines) {
            printf(important,"%s%s%s", prefix, indent, line);
        }
    }

    @Override
    public void important(String message, Throwable e) {
        important(String.format("%s%n%s", message, Utils.toString(e)));
    }

    @Override
    synchronized public void achtung(String format, Object... values) {
        String line = String.format(format, values);
        for (OutputListener listener : listeners) {
            listener.receivedAchtung(line);
        }
        printf(achtung, "%sachtung: %s", prefix, line);
    }

    @Override
    synchronized public void achtung(String message, Throwable e) {
        achtung(String.format("%s%n%s", message, Utils.toString(e)));
    }

    @Override
    public void add(Line line) {
        lines.add(line);
    }

    @Override
    public void add(Output output) {
        for (Line line : output.lines()) {
            add(line);
        }
    }

    @Override
    public void add(Output output, Level level) {
        for (Line line : output.lines()) {
            add(new Line(level, line.value()));
        }
    }

    @Override
    synchronized public List<Line> lines() {
        return Collections.unmodifiableList(lines);
    }

    @Override
    synchronized public boolean contains(String phrase) {
        for (Line line : lines) {
            if (line.contains(phrase)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void clear() {
        lines.clear();
    }

    @Override
    synchronized public void flush() {
        // do nothing
    }

    @Override
    synchronized public void close() {
        flush();
    }

}
