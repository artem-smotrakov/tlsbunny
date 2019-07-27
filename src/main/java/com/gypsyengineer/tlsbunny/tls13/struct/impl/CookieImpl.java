package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.Cookie;

import java.io.IOException;
import java.util.Objects;

public class CookieImpl implements Cookie {

    private Vector<Byte> cookie;

    CookieImpl(Vector<Byte> cookie) {
        this.cookie = cookie;
    }

    @Override
    public Vector<Byte> getCookie() {
        return cookie;
    }

    @Override
    public int encodingLength() {
        return cookie.encodingLength();
    }

    @Override
    public byte[] encoding() throws IOException {
        return cookie.encoding();
    }

    @Override
    public CookieImpl copy() {
        return new CookieImpl((Vector<Byte>) cookie.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CookieImpl cookie1 = (CookieImpl) o;
        return Objects.equals(cookie, cookie1.cookie);
    }

    @Override
    public int hashCode() {
        return Objects.hash(cookie);
    }
}
