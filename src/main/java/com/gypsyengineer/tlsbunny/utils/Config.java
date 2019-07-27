package com.gypsyengineer.tlsbunny.utils;

public interface Config {
    String host();
    int port();
    double minRatio();
    double maxRatio();
    int threads();
    int parts();
    long total();
    String clientCertificate();
    String clientKey();
    String serverCertificate();
    String serverKey();
    String targetFilter();
    String state();

    // timeout for reading incoming data (in millis)
    long readTimeout();

    Config host(String host);
    Config port(int port);
    Config minRatio(double minRatio);
    Config maxRatio(double maxRatio);
    Config total(long n);
    Config parts(int parts);
    Config readTimeout(long timeout);
    Config clientCertificate(String path);
    Config clientKey(String path);
    Config serverCertificate(String path);
    Config serverKey(String path);
    Config state(String state);

    boolean hasState();

    /**
     * @return a copy of the config
     */
    Config copy();
}
