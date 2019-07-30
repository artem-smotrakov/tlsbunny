package com.gypsyengineer.tlsbunny.tls13.connection.action;

import com.gypsyengineer.tlsbunny.tls13.handshake.Context;

import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.utils.Utils.cantDoThat;

/**
 * This is an action that does nothing.
 */
public class EmptyAction implements Action {

    @Override
    public String name() {
        return "I am a fake action, you're probably not supposed to call this method!";
    }

    @Override
    public Action set(Context context) {
        return this;
    }

    @Override
    public Action run() {
        return this;
    }

    @Override
    public Action in(byte[] bytes) {
        return this;
    }

    @Override
    public Action in(ByteBuffer buffer) {
        throw cantDoThat();
    }

    @Override
    public ByteBuffer out() {
        throw cantDoThat();
    }

    @Override
    public Action applicationData(ByteBuffer buffer) {
        return this;
    }

    @Override
    public ByteBuffer applicationData() {
        throw cantDoThat();
    }
}
