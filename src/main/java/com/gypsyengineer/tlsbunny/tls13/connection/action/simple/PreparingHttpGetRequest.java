package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

public class PreparingHttpGetRequest extends PreparingApplicationData {

    public static final String HTTP_GET_REQUEST_TEMPLATE = "GET %s HTTP/1.1\n\n";
    public static final String DEFAULT_PATH = "/";

    public PreparingHttpGetRequest(String path) {
        super(String.format(HTTP_GET_REQUEST_TEMPLATE, path).getBytes());
    }

    public PreparingHttpGetRequest() {
        this(DEFAULT_PATH);
    }

    @Override
    public String name() {
        return "generating HTTP GET request";
    }

}
