package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;

public class AlertDescriptionImpl implements AlertDescription {

    private final int code;

    AlertDescriptionImpl(int code) {
        check(code);
        this.code = code;
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
    public AlertDescriptionImpl copy() {
        return new AlertDescriptionImpl(code);
    }

    @Override
    public byte getCode() {
        return (byte) code;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + this.code;
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
        final AlertDescriptionImpl other = (AlertDescriptionImpl) obj;
        return this.code == other.code;
    }

    @Override
    public String toString() {
        return String.format("alert_description (%d)", code);
    }

    private static void check(int code) {
        if (code < min || code > max) {
            throw new IllegalArgumentException();
        }
    }

}
