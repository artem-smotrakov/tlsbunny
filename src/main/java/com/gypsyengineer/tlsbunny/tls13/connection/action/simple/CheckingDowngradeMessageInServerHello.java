package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;

import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.utils.Achtung.achtung;
import static com.gypsyengineer.tlsbunny.utils.Utils.lastBytesEquals;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class CheckingDowngradeMessageInServerHello
        extends AbstractAction<CheckingDowngradeMessageInServerHello> {

    private static final byte[] downgrade_message_tls12 = {
            0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
    };

    private static final byte[] downgrade_message_tls11_or_below = {
            0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
    };

    private ProtocolVersion expectedVersion = TLSv13;

    public CheckingDowngradeMessageInServerHello expect(ProtocolVersion version) {
        if (version == null) {
            throw whatTheHell("version is null!");
        }

        expectedVersion = version;

        return this;
    }

    @Override
    public String name() {
        return String.format("checking a downgrade message in ServerHello, expect: %s",
                expectedVersion);
    }

    @Override
    public CheckingDowngradeMessageInServerHello run() {
        context.factory().parser().parseProtocolVersion(in);

        byte[] bytes = Random.parse(in).getBytes();

        if (TLSv13.equals(expectedVersion)) {
            if (lastBytesEquals(bytes, downgrade_message_tls12)) {
                throw achtung("found a downgrade message in ServerHello (TLSv12)");
            }

            if (lastBytesEquals(bytes, downgrade_message_tls11_or_below)) {
                throw achtung("found a downgrade message in ServerHello (TLSv11 or below)");
            }

            output.info("no downgrade message found in ServerHello");
        } else if (ProtocolVersion.TLSv12.equals(expectedVersion)) {
            if (!lastBytesEquals(bytes, downgrade_message_tls12)) {
                throw achtung("no downgrade message found in ServerHello (TLSv12)");
            }

            output.info("found a downgrade message in ServerHello (TLSv12)");
        } else {
            if (!lastBytesEquals(bytes, downgrade_message_tls11_or_below)) {
                throw achtung("no downgrade message found in ServerHello (TLSv11 or below)");
            }

            output.info("found a downgrade message in ServerHello (TLSv11 or below)");
        }

        // ignore the rest of the message

        return this;
    }

}
