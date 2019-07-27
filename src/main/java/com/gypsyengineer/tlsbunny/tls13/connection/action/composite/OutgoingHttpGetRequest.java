package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

public class OutgoingHttpGetRequest extends OutgoingApplicationData {

    public static final String HTTP_GET_REQUEST_TEMPLATE = "GET %s HTTP/1.1\n\n";
    public static final String DEFAULT_PATH = "/";

    public OutgoingHttpGetRequest() {
        this(DEFAULT_PATH);
    }

    public OutgoingHttpGetRequest(String path) {
        super(String.format(HTTP_GET_REQUEST_TEMPLATE, path));
    }
}
