package com.gypsyengineer.tlsbunny.tls13.connection;

public interface Analyzer {
    Analyzer add(Engine... engines);
    Analyzer run();
    Engine[] engines();
}
