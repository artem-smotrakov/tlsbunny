package com.gypsyengineer.tlsbunny.output;

import java.io.InputStream;
import java.util.List;

public interface Output extends AutoCloseable {

    // global output level
    Level level = Level.valueOf(
            System.getProperty("tlsbunny.output.level", Level.info.name()));

    static FileOutput file(String filename) {
        return new FileOutput(local(), filename);
    }

    static StandardOutput standard() {
        return new StandardOutput(local());
    }

    static StandardOutput standard(String prefix) {
        return new StandardOutput(local(prefix));
    }

    static StandardOutput standard(Output output) {
        return new StandardOutput(output);
    }

    static StandardOutput standardClient() {
        return standard("client");
    }

    static LocalOutput local() {
        return new LocalOutput();
    }

    static LocalOutput local(String prefix) {
        return new LocalOutput(prefix);
    }

    static InputStreamOutput create(InputStream is) {
        return new InputStreamOutput().set(is);
    }

    Output add(OutputListener listener);

    void increaseIndent();

    void decreaseIndent();

    void prefix(String prefix);

    void info(String format, Object... values);

    void info(String message, Throwable e);

    void important(String format, Object... values);

    void important(String message, Throwable e);

    void achtung(String format, Object... values);

    void achtung(String message, Throwable e);

    void add(Line line);

    void add(Output output);

    void add(Output output, Level level);

    List<Line> lines();

    boolean contains(String line);

    void clear();

    void flush();

    @Override
    void close();
}
