package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.crypto.TranscriptHash;
import com.gypsyengineer.tlsbunny.tls13.handshake.Constants;
import com.gypsyengineer.tlsbunny.tls13.struct.Finished;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.tls13.handshake.Constants.zero_hash_value;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class ProcessingFinished extends AbstractAction<ProcessingFinished> {

    private Side side;

    public ProcessingFinished() {
        this(Side.client);
    }

    public ProcessingFinished(Side side) {
        this.side = side;
    }

    @Override
    public String name() {
        return String.format("processing Finished (%s)", side);
    }

    public ProcessingFinished side(Side side) {
        this.side = side;
        return this;
    }

    public ProcessingFinished server() {
        side = Side.server;
        return this;
    }

    public ProcessingFinished client() {
        side = Side.client;
        return this;
    }

    @Override
    public Action run() throws IOException, ActionFailed {
        if (side == null) {
            throw whatTheHell("side not specified! (null)");
        }

        Finished finished = context.factory().parser().parseFinished(
                in, context.suite().hashLength());

        byte[] verify_key = context.hkdf().expandLabel(
                getBaseKey(),
                Constants.finished(),
                zero_hash_value,
                context.hkdf().getHashLength());

        byte[] verify_data;
        try {
            verify_data = context.hkdf().hmac(
                    verify_key,
                    TranscriptHash.compute(context.suite().hash(), context.allMessages()));
        } catch (NoSuchAlgorithmException e) {
            throw new ActionFailed(e);
        }

        boolean success = Arrays.equals(verify_data, finished.getVerifyData());
        if (!success) {
            throw new ActionFailed("verification of Finished failed");
        }

        switch (side) {
            case client:
                context.verifyServerFinished();
                break;
            case server:
                context.verifyClientFinished();
                break;
            default:
                throw whatTheHell("unknown side: " + side);
        }

        output.info("verified Finished message");

        return this;
    }

    private byte[] getBaseKey() {
        switch (side) {
            case client:
                return context.server_handshake_traffic_secret();
            case server:
                return context.client_handshake_traffic_secret();
            default:
                throw whatTheHell("unknown side: " + side);
        }
    }

}
