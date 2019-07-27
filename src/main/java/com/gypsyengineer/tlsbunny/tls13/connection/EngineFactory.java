package com.gypsyengineer.tlsbunny.tls13.connection;

import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;


public interface EngineFactory {

    EngineFactory set(StructFactory factory);
    StructFactory structFactory();
    Engine create() throws EngineException;
}
