package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec;

public class ProcessingChangeCipherSpec extends AbstractAction<ProcessingChangeCipherSpec> {

    @Override
    public String name() {
        return "processing ChangeCipherSpec";
    }

    @Override
    public Action run() throws ActionFailed {
        ChangeCipherSpec ccs = context.factory().parser().parseChangeCipherSpec(in);
        if (!ccs.isValid()) {
            throw new ActionFailed("unexpected content in change_cipher_spec message");
        }

        return this;
    }

}
