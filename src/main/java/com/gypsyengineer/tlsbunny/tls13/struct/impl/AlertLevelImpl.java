package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;

public class AlertLevelImpl implements AlertLevel {

    private final int code;

    AlertLevelImpl(int code) {
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
    public AlertLevelImpl copy() {
        return new AlertLevelImpl(code);
    }

    @Override
    public byte getCode() {
        return (byte) code;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + this.code;
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
        final AlertLevelImpl other = (AlertLevelImpl) obj;
        return this.code == other.code;
    }

    @Override
    public String toString() {
        if (code == fatal.getCode()) {
            return "fatal";
        } else if (code == warning.getCode()) {
            return "warning";
        }

        return "unknown";
    }

    private static void check(int code) {
        if (code < min || code > max) {
            throw new IllegalArgumentException();
        }
    }

}
