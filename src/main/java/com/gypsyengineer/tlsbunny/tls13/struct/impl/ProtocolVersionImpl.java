package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;

public class ProtocolVersionImpl implements ProtocolVersion {

    private final int major;
    private final int minor;

    ProtocolVersionImpl(int major, int minor) {
        check(minor, major);
        this.major = major;
        this.minor = minor;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() throws IOException {
        return ByteBuffer.allocate(2).put((byte) major).put((byte) minor).array();
    }

    @Override
    public ProtocolVersionImpl copy() {
        return new ProtocolVersionImpl(major, minor);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 17 * hash + this.major;
        hash = 17 * hash + this.minor;
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
        final ProtocolVersionImpl other = (ProtocolVersionImpl) obj;
        if (this.major != other.major) {
            return false;
        }
        return this.minor == other.minor;
    }

    private static void check(int minor, int major) {
        if (major < 0 || major > 255 || minor < 0 || minor > 255) {
            throw new IllegalArgumentException();
        }
    }

    @Override
    public String toString() {
        // yes, the multiple ifs below look just terrible
        // although it's not clear how to avoid them:
        // - "switch" doesn't work because we can't use ProtocolVersion.getMinor() for "case"
        // - creating a map {code, description} doesn't work because standard types in ProtocolVersion
        //   are not initialized at the moment of initializing of the map
        String template = "protocol version (0x%s%s)";
        if (SSLv3.getMinor() == minor && SSLv3.getMajor() == major) {
            template = "SSLv3 (0x%s%s)";
        }
        if (TLSv10.getMinor() == minor && TLSv10.getMajor() == major) {
            template = "TLSv10 (0x%s%s)";
        }
        if (TLSv11.getMinor() == minor && TLSv11.getMajor() == major) {
            template = "TLSv11 (0x%s%s)";
        }
        if (TLSv12.getMinor() == minor && TLSv12.getMajor() == major) {
            template = "TLSv12 (0x%s%s)";
        }
        if (TLSv13.getMinor() == minor && TLSv13.getMajor() == major) {
            template = "TLSv13 (0x%s%s)";
        }

        return String.format(template, Integer.toHexString(major), Integer.toHexString(minor));
    }

    @Override
    public int getMinor() {
        return minor;
    }

    @Override
    public int getMajor() {
        return major;
    }
}
