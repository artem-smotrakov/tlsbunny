package com.gypsyengineer.tlsbunny.utils;

import java.util.Objects;

public class SystemPropertiesConfig implements Config {

    public static final int default_parts = 1;
    public static final int default_port = 10101;
    public static final int default_threads = 1;
    public static final long default_total = 1000;
    public static final long default_read_timeout = 5000; // in millis
    public static final double default_min_ratio = 0.01;
    public static final double default_max_ratio = 0.05;
    public static final String default_host = "localhost";
    public static final String default_server_certificate = "certs/server_cert.der";
    public static final String default_server_key = "certs/server_key.pkcs8";
    public static final String default_client_certificate = "certs/client_cert.der";
    public static final String default_client_key = "certs/client_key.pkcs8";
    public static final String empty_string = "";

    private IntegerValue port = new IntegerValue("tlsbunny.port", default_port);
    private IntegerValue threads = new IntegerValue("tlsbunny.threads", default_threads);
    private IntegerValue parts = new IntegerValue("tlsbunny.parts", default_parts);
    private DoubleValue minRatio = new DoubleValue("tlsbunny.min.ratio", default_min_ratio);
    private DoubleValue maxRatio = new DoubleValue("tlsbunny.max.ratio", default_max_ratio);
    private LongValue total = new LongValue("tlsbunny.total", default_total);
    private LongValue readTimeout = new LongValue("tlsbunny.read.timeout", default_read_timeout);
    private StringValue clientCertificate = new StringValue("tlsbunny.client.cert", default_client_certificate);
    private StringValue clientKey = new StringValue("tlsbunny.client.key", default_client_key);
    private StringValue serverCertificate = new StringValue("tlsbunny.server.cert", default_server_certificate);
    private StringValue serverKey = new StringValue("tlsbunny.server.key", default_server_key);
    private StringValue state = new StringValue("tlsbunny.state", empty_string);
    private StringValue targetFilter = new StringValue("tlsbunny.target.filter", empty_string);
    private StringValue host = new StringValue("tlsbunny.host", default_host);

    private SystemPropertiesConfig() {

    }

    @Override
    synchronized public SystemPropertiesConfig copy() {
        SystemPropertiesConfig clone = new SystemPropertiesConfig();
        clone.host = host.copy();
        clone.port = port.copy();
        clone.minRatio = minRatio.copy();
        clone.maxRatio = maxRatio.copy();
        clone.threads = threads.copy();
        clone.parts = parts.copy();
        clone.clientCertificate = clientCertificate.copy();
        clone.clientKey = clientKey.copy();
        clone.serverCertificate = serverCertificate.copy();
        clone.serverKey = serverKey.copy();
        clone.readTimeout = readTimeout.copy();
        clone.total = total.copy();
        clone.state = state.copy();
        clone.targetFilter = targetFilter.copy();

        return clone;
    }

    @Override
    synchronized public Config host(String value) {
        host.set(value);
        return this;
    }

    @Override
    synchronized public Config port(int n) {
        port.set(n);
        return this;
    }

    @Override
    synchronized public Config minRatio(double value) {
        minRatio.set(value);
        return this;
    }

    @Override
    synchronized public Config maxRatio(double value) {
        maxRatio.set(value);
        return this;
    }

    @Override
    public Config total(long n) {
        total.set(n);
        return this;
    }

    @Override
    synchronized public Config parts(int n) {
        parts.set(n);
        return this;
    }

    @Override
    synchronized public Config readTimeout(long n) {
        readTimeout.set(n);
        return this;
    }

    @Override
    synchronized public Config clientCertificate(String path) {
        clientCertificate.set(path);
        return this;
    }

    @Override
    synchronized public Config clientKey(String path) {
        clientKey.set(path);
        return this;
    }

    @Override
    synchronized public Config serverCertificate(String path) {
        serverCertificate.set(path);
        return this;
    }

    @Override
    synchronized public Config serverKey(String path) {
        serverKey.set(path);
        return this;
    }

    @Override
    synchronized public Config state(String value) {
        state.set(value);
        return this;
    }

    @Override
    synchronized public boolean hasState() {
        return state.available();
    }

    @Override
    synchronized public String host() {
        return host.get();
    }

    @Override
    synchronized public int port() {
        return port.get();
    }

    @Override
    synchronized public double minRatio() {
        return minRatio.get();
    }

    @Override
    synchronized public double maxRatio() {
        return maxRatio.get();
    }

    @Override
    synchronized public int threads() {
        return threads.get();
    }

    @Override
    synchronized public int parts() {
        return parts.get();
    }

    @Override
    public long total() {
        return total.get();
    }

    @Override
    synchronized public String clientCertificate() {
        return clientCertificate.get();
    }

    @Override
    synchronized public String clientKey() {
        return clientKey.get();
    }

    @Override
    synchronized public String serverCertificate() {
        return serverCertificate.get();
    }

    @Override
    public String serverKey() {
        return serverKey.get();
    }

    @Override
    synchronized public long readTimeout() {
        return readTimeout.get();
    }

    @Override
    synchronized public String targetFilter() {
        return targetFilter.get();
    }

    @Override
    synchronized public String state() {
        return state.get();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SystemPropertiesConfig that = (SystemPropertiesConfig) o;
        return Objects.equals(port, that.port) &&
                Objects.equals(threads, that.threads) &&
                Objects.equals(parts, that.parts) &&
                Objects.equals(minRatio, that.minRatio) &&
                Objects.equals(maxRatio, that.maxRatio) &&
                Objects.equals(total, that.total) &&
                Objects.equals(readTimeout, that.readTimeout) &&
                Objects.equals(clientCertificate, that.clientCertificate) &&
                Objects.equals(clientKey, that.clientKey) &&
                Objects.equals(serverCertificate, that.serverCertificate) &&
                Objects.equals(serverKey, that.serverKey) &&
                Objects.equals(state, that.state) &&
                Objects.equals(targetFilter, that.targetFilter) &&
                Objects.equals(host, that.host);
    }

    @Override
    public int hashCode() {
        return Objects.hash(port, threads, parts, minRatio, maxRatio, total,
                readTimeout, clientCertificate, clientKey, serverCertificate,
                serverKey, state, targetFilter, host);
    }

    public static SystemPropertiesConfig load() {
        return new SystemPropertiesConfig();
    }

    private abstract static class Value {

        final String property;

        Value(String property) {
            this.property = property;
        }

        boolean defined() {
            return System.getProperty(property) != null;
        }
    }

    private static class IntegerValue extends Value {

        private int value;

        IntegerValue(String property, int defaultValue) {
            super(property);
            value = defaultValue;
        }

        int get() {
            if (defined()) {
                return Integer.getInteger(property);
            }

            return value;
        }

        void set(int value) {
            if (defined()) {
                return;
            }

            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            IntegerValue that = (IntegerValue) o;
            return value == that.value;
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }

        public IntegerValue copy() {
            return new IntegerValue(property, value);
        }
    }

    private static class LongValue extends Value {

        private long value;

        LongValue(String property, long defaultValue) {
            super(property);
            value = defaultValue;
        }

        long get() {
            if (defined()) {
                return Long.getLong(property);
            }

            return value;
        }

        void set(long value) {
            if (defined()) {
                return;
            }

            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            LongValue longValue = (LongValue) o;
            return value == longValue.value;
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }

        public LongValue copy() {
            return new LongValue(property, value);
        }
    }

    private static class DoubleValue extends Value {

        private double value;

        DoubleValue(String property, double defaultValue) {
            super(property);
            value = defaultValue;
        }

        double get() {
            if (defined()) {
                return Double.parseDouble(System.getProperty(property));
            }

            return value;
        }

        void set(double value) {
            if (defined()) {
                return;
            }

            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            DoubleValue that = (DoubleValue) o;
            return Double.compare(that.value, value) == 0;
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }

        public DoubleValue copy() {
            return new DoubleValue(property, value);
        }
    }

    private static class StringValue extends Value {

        private String value;

        StringValue(String property, String defaultValue) {
            super(property);
            value = defaultValue;
        }

        String get() {
            if (defined()) {
                return System.getProperty(property).trim();
            }

            return value;
        }

        void set(String value) {
            if (defined()) {
                return;
            }

            this.value = value;
        }

        boolean available() {
            String s = get();
            return s != null && !s.isEmpty();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            StringValue that = (StringValue) o;
            return Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }

        public StringValue copy() {
            return new StringValue(property, value);
        }
    }

}
