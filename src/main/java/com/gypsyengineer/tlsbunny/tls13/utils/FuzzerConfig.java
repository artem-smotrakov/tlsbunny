package com.gypsyengineer.tlsbunny.tls13.utils;

import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;

import java.util.Objects;

public class FuzzerConfig implements Config {

    private Config mainConfig;
    private StructFactory factory;

    public FuzzerConfig(Config mainConfig) {
        this.mainConfig = mainConfig.copy();
    }

    @Override
    synchronized public FuzzerConfig copy() {
        FuzzerConfig clone = new FuzzerConfig(mainConfig);
        clone.factory = factory;

        return clone;
    }

    synchronized public FuzzerConfig set(Config mainConfig) {
        this.mainConfig = mainConfig;
        return this;
    }

    @Override
    synchronized public String host() {
        return mainConfig.host();
    }

    @Override
    synchronized public int port() {
        return mainConfig.port();
    }

    @Override
    synchronized public double minRatio() {
        return mainConfig.minRatio();
    }

    @Override
    synchronized public double maxRatio() {
        return mainConfig.maxRatio();
    }

    @Override
    synchronized public int threads() {
        return mainConfig.threads();
    }

    @Override
    synchronized public int parts() {
        return mainConfig.parts();
    }

    @Override
    public long total() {
        return mainConfig.total();
    }

    @Override
    synchronized public String clientCertificate() {
        return mainConfig.clientCertificate();
    }

    @Override
    synchronized public String clientKey() {
        return mainConfig.clientKey();
    }

    @Override
    synchronized public String serverCertificate() {
        return mainConfig.serverCertificate();
    }

    @Override
    synchronized public String serverKey() {
        return mainConfig.serverKey();
    }

    @Override
    synchronized public String targetFilter() {
        return mainConfig.targetFilter();
    }

    @Override
    public String state() {
        return mainConfig.state();
    }

    @Override
    synchronized public long readTimeout() {
        return mainConfig.readTimeout();
    }

    @Override
    synchronized public Config host(String host) {
        mainConfig.host(host);
        return this;
    }

    @Override
    synchronized public Config port(int port) {
        mainConfig.port(port);
        return this;
    }

    @Override
    synchronized public FuzzerConfig minRatio(double minRatio) {
        mainConfig.minRatio(minRatio);
        return this;
    }

    @Override
    synchronized public FuzzerConfig maxRatio(double maxRatio) {
        mainConfig.maxRatio(maxRatio);
        return this;
    }

    @Override
    public FuzzerConfig total(long n) {
        mainConfig.total(n);
        return this;
    }

    @Override
    synchronized public FuzzerConfig parts(int parts) {
        mainConfig.parts(parts);
        return this;
    }

    @Override
    synchronized public FuzzerConfig readTimeout(long timeout) {
        mainConfig.readTimeout(timeout);
        return this;
    }

    @Override
    synchronized public Config clientCertificate(String path) {
        mainConfig.clientCertificate(path);
        return this;
    }

    @Override
    synchronized public Config clientKey(String path) {
        mainConfig.clientKey(path);
        return this;
    }

    @Override
    synchronized public Config serverCertificate(String path) {
        mainConfig.serverCertificate(path);
        return this;
    }

    @Override
    synchronized public Config serverKey(String path) {
        mainConfig.serverKey(path);
        return this;
    }

    @Override
    public Config state(String state) {
        mainConfig.state(state);
        return this;
    }

    @Override
    public boolean hasState() {
        return mainConfig.hasState();
    }

    synchronized public boolean noFactory() {
        return factory == null;
    }

    synchronized public FuzzerConfig factory(StructFactory factory) {
        this.factory = factory;
        return this;
    }

    synchronized public StructFactory factory() {
        return factory;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        FuzzerConfig config = (FuzzerConfig) o;
        return Objects.equals(mainConfig, config.mainConfig) &&
                Objects.equals(factory, config.factory);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mainConfig, factory);
    }
}
