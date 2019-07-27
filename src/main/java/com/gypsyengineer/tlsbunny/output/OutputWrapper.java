package com.gypsyengineer.tlsbunny.output;

import java.util.List;

public abstract class OutputWrapper implements Output {

    protected final Output output;
    Level minLevel;

    OutputWrapper(Output output) {
        this(output, Output.level);
    }

    OutputWrapper(Output output, Level minLevel) {
        this.output = output;
        this.minLevel = minLevel;
    }

    @Override
    synchronized public Output add(OutputListener listener) {
        output.add(listener);
        return this;
    }

    @Override
    public void increaseIndent() {
        output.increaseIndent();
    }

    @Override
    public void decreaseIndent() {
        output.decreaseIndent();
    }

    @Override
    public void prefix(String prefix) {
        output.prefix(prefix);
    }

    @Override
    public void info(String format, Object... values) {
        output.info(format, values);
    }

    @Override
    public void info(String message, Throwable e) {
        output.info(message, e);
    }

    @Override
    public void achtung(String format, Object... values) {
        output.achtung(format, values);
    }

    @Override
    public void achtung(String message, Throwable e) {
        output.achtung(message, e);
    }

    @Override
    public List<Line> lines() {
        return output.lines();
    }

    @Override
    public boolean contains(String line) {
        return output.contains(line);
    }

    @Override
    public void clear() {
        output.clear();
    }

    @Override
    public void flush() {
        output.flush();
    }

    @Override
    public void close() {
        output.close();
    }

    @Override
    public void add(Line line) {
        output.add(line);
    }

    @Override
    public void add(Output output) {
        this.output.add(output);
    }

    @Override
    public void important(String format, Object... values) {
        output.important(format, values);
    }

    @Override
    public void important(String message, Throwable e) {
        output.important(message, e);
    }

    @Override
    public void add(Output output, Level level) {
        this.output.add(output, level);
    }
}
