package com.gypsyengineer.tlsbunny.tls13.connection;

import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;

public abstract class BaseEngineFactory implements EngineFactory {

    protected Config config = SystemPropertiesConfig.load();
    protected StructFactory structFactory = StructFactory.getDefault();
    protected Output output = Output.local(String.format("output-%s-%d",
            BaseEngineFactory.class.getSimpleName(), System.currentTimeMillis()));

    public BaseEngineFactory set(Config config) {
        this.config = config;
        return this;
    }

    @Override
    public BaseEngineFactory set(StructFactory factory) {
        structFactory = factory;
        return this;
    }

    @Override
    public BaseEngineFactory set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public StructFactory structFactory() {
        return structFactory;
    }

    @Override
    public Output output() {
        return output;
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
