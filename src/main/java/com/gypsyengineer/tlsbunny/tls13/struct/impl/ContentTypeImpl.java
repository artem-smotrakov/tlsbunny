package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class ContentTypeImpl implements ContentType {

    private final int code;

    ContentTypeImpl(int code) {
        check(code);
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }

    @Override
    public boolean isHandshake() {
        return code == handshake.getCode();
    }

    @Override
    public boolean isApplicationData() {
        return code == application_data.getCode();
    }

    @Override
    public boolean isAlert() {
        return code == alert.getCode();
    }

    @Override
    public boolean isChangeCipherSpec() {
        return code == change_cipher_spec.getCode();
    }

    @Override
    public boolean isInvalid() {
        return code == invalid.getCode();
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() {
        return new byte[] { (byte) code };
    }

    @Override
    public ContentTypeImpl copy() {
        return new ContentTypeImpl(code);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + this.code;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ContentTypeImpl other = (ContentTypeImpl) obj;
        return this.code == other.code;
    }

    @Override
    public String toString() {
        // yes, the multiple ifs below look just terrible
        // although it's not clear how to avoid them:
        // - "switch" doesn't work because we can't use ContentType.getCode() for "case"
        // - creating a map {code, description} doesn't work because standard types in ContentType
        //   are not initialized at the moment of initializing of the map
        String template = "content type (%d)";
        if (isAlert()) {
            template = "alert (%s)";
        }
        if (isHandshake()) {
            template = "handshake (%s)";
        }
        if (isApplicationData()) {
            template = "application_data (%s)";
        }
        if (isChangeCipherSpec()) {
            template = "change_cipher_spec (%s)";
        }
        if (isInvalid()) {
            template = "invalid (%s)";
        }
        return String.format(template, code);
    }

    private static void check(int code) {
        if (code < 0 || code > 255) {
            throw whatTheHell("code is wrong: %s", code);
        }
    }

}
