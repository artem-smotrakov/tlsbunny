package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.crypto.TranscriptHash;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class GeneratingFinished extends AbstractAction {

    private Side side;

    public GeneratingFinished() {
        this(Side.client);
    }

    public GeneratingFinished(Side side) {
        this.side = side;
    }

    @Override
    public String name() {
        return String.format("generating Finished (%s)", side);
    }

    public GeneratingFinished side(Side side) {
        this.side = side;
        return this;
    }

    public GeneratingFinished server() {
        side = Side.server;
        return this;
    }

    public GeneratingFinished client() {
        side = Side.client;
        return this;
    }

    @Override
    public Action run() throws IOException, ActionFailed {
        if (side == null) {
            throw whatTheHell("side not specified! (null)");
        }

        byte[] finished_key = context.finished_key();
        if (finished_key == null || finished_key.length == 0) {
            throw new ActionFailed("finished_key is empty!");
        }

        try {
            byte[] verify_data = context.hkdf().hmac(
                    context.finished_key(),
                    TranscriptHash.compute(context.suite().hash(), context.allMessages()));

            Finished finished = context.factory().createFinished(verify_data);
            out = ByteBuffer.wrap(finished.encoding());
        } catch (NoSuchAlgorithmException e) {
            throw new ActionFailed(e);
        }

        switch (side) {
            case client:
                context.verifyClientFinished();
                break;
            case server:
                context.verifyServerFinished();
                break;
            default:
                throw whatTheHell("unknown side: " + side);
        }

        return this;
    }
}
