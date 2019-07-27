package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import java.io.IOException;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class IncomingChangeCipherSpec extends AbstractAction {

    private int expectedValue = -1;

    @Override
    public String name() {
        return "incoming ChangeCipherSpec";
    }

    public IncomingChangeCipherSpec expect(int ccsValue) {
        if (ccsValue < 0 || ccsValue > 255) {
            throw whatTheHell("invalid CCS value (%d)", ccsValue);
        }

        expectedValue = ccsValue;
        return this;
    }

    @Override
    public IncomingChangeCipherSpec run() throws ActionFailed, IOException {
        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);
        if (!tlsPlaintext.containsChangeCipherSpec()) {
            throw new ActionFailed("expected a change cipher spec message");
        }

        ChangeCipherSpec ccs = context.factory().parser().parseChangeCipherSpec(
                tlsPlaintext.getFragment());

        if (expectedValue != -1 && ccs.getValue() != expectedValue) {
            throw new ActionFailed(String.format(
                    "unexpected content in change_cipher_spec message", ccs.getValue()));
        }

        return this;
    }

}
