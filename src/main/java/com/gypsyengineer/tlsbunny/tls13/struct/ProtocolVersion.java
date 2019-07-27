package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface ProtocolVersion extends Struct {

    int encoding_length = 2;

    ProtocolVersion SSLv3  = StructFactory.getDefault()
            .createProtocolVersion(0x3, 0x0);
    ProtocolVersion TLSv10 = StructFactory.getDefault()
            .createProtocolVersion(0x3, 0x1);
    ProtocolVersion TLSv11 = StructFactory.getDefault()
            .createProtocolVersion(0x3, 0x2);
    ProtocolVersion TLSv12 = StructFactory.getDefault()
            .createProtocolVersion(0x3, 0x3);
    ProtocolVersion TLSv13 = StructFactory.getDefault()
            .createProtocolVersion(0x3, 0x4);

    ProtocolVersion TLSv13_draft_26 = StructFactory.getDefault()
            .createProtocolVersion(0x7f, 0x1a);

    ProtocolVersion TLSv13_draft_28 = StructFactory.getDefault()
            .createProtocolVersion(0x7f, 0x1c);

    int getMinor();
    int getMajor();
}
