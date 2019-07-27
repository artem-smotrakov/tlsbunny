package com.gypsyengineer.tlsbunny.tls13.utils;

import com.gypsyengineer.tlsbunny.utils.Config;

public class FuzzerConfigUpdater implements Config {

    private final FuzzerConfig[] configs;

    public static FuzzerConfigUpdater fuzzerConfigUpdater(FuzzerConfig... configs) {
        return new FuzzerConfigUpdater(configs);
    }

    private FuzzerConfigUpdater(FuzzerConfig... configs) {
        this.configs = configs;
    }

    @Override
    public String host() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int port() {
        throw new UnsupportedOperationException();
    }

    @Override
    public double minRatio() {
        throw new UnsupportedOperationException();
    }

    @Override
    public double maxRatio() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int threads() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int parts() {
        throw new UnsupportedOperationException();
    }

    @Override
    public long total() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String clientCertificate() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String clientKey() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String serverCertificate() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String serverKey() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String targetFilter() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String state() {
        throw new UnsupportedOperationException();
    }

    @Override
    public long readTimeout() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Config host(String host) {
        for (Config config : configs) {
            config.host(host);
        }
        return this;
    }

    @Override
    public Config port(int port) {
        for (Config config : configs) {
            config.port(port);
        }
        return this;
    }

    @Override
    public Config minRatio(double minRatio) {
        for (Config config : configs) {
            config.minRatio(minRatio);
        }
        return null;
    }

    @Override
    public Config maxRatio(double maxRatio) {
        for (Config config : configs) {
            config.maxRatio(maxRatio);
        }
        return null;
    }

    @Override
    public Config total(long n) {
        for (Config config : configs) {
            config.total(n);
        }
        return null;
    }

    @Override
    public Config parts(int parts) {
        for (Config config : configs) {
            config.parts(parts);
        }
        return null;
    }

    @Override
    public Config readTimeout(long timeout) {
        for (Config config : configs) {
            config.readTimeout(timeout);
        }
        return null;
    }

    @Override
    public Config clientCertificate(String path) {
        for (Config config : configs) {
            config.clientCertificate(path);
        }
        return null;
    }

    @Override
    public Config clientKey(String path) {
        for (Config config : configs) {
            config.clientKey(path);
        }
        return null;
    }

    @Override
    public Config serverCertificate(String path) {
        for (Config config : configs) {
            config.serverCertificate(path);
        }
        return null;
    }

    @Override
    public Config serverKey(String path) {
        for (Config config : configs) {
            config.serverKey(path);
        }
        return null;
    }

    @Override
    public Config state(String state) {
        for (Config config : configs) {
            config.state(state);
        }
        return null;
    }

    @Override
    public boolean hasState() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Config copy() {
        throw new UnsupportedOperationException();
    }
}
