package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt32;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface PskIdentity extends Struct {

    int identity_length_bytes = 2;

    Vector<Byte> identity();
    UInt32 obfuscatedTicketAge();
}
