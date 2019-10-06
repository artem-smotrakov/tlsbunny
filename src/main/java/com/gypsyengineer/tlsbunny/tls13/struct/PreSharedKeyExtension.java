package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt16;

public interface PreSharedKeyExtension extends Struct {

    interface ClientHello extends PreSharedKeyExtension {
        OfferedPsks offeredPsks();
    }

    interface ServerHello extends PreSharedKeyExtension {
        UInt16 selectedIdentity();
    }
}
