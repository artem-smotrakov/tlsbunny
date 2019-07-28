package com.gypsyengineer.tlsbunny.tls13.connection;

import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

public abstract class BaseEngineFactory implements EngineFactory {

    protected StructFactory structFactory = StructFactory.getDefault();

    @Override
    public BaseEngineFactory set(StructFactory factory) {
        structFactory = factory;
        return this;
    }

    @Override
    public StructFactory structFactory() {
        return structFactory;
    }

    @Override
    public final Engine create() throws EngineException {
        try {
            return createImpl();
        } catch (Exception e) {
            throw new EngineException("could not create an engine", e);
        }
    }

    protected abstract Engine createImpl() throws Exception;

}
