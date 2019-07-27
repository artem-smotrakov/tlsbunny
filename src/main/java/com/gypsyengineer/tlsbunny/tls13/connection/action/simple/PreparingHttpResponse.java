package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

// TODO: generate a full HTTP response (200 code), but not just an HTML page
public class PreparingHttpResponse extends PreparingApplicationData {

    private static final byte[] HTML_PAGE =
            "<html>Like most of life's problems, this one can be solved with bending!<html>"
                    .getBytes();

    public PreparingHttpResponse() {
        super(HTML_PAGE);
    }

    @Override
    public String name() {
        return "generating HTTP response";
    }

}