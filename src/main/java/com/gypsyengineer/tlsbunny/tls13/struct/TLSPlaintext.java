package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt16;

public interface TLSPlaintext extends Struct {

    int max_allowed_length = 16384;

    // it's the length of an empty TLSPlaintext structure
    int MIN_ENCODING_LENGTH = ContentType.encoding_length
            + ProtocolVersion.encoding_length
            + UInt16.encoding_length;

    boolean containsAlert();
    boolean containsApplicationData();
    boolean containsHandshake();
    boolean containsChangeCipherSpec();
    byte[] getFragment();
    ProtocolVersion getLegacyRecordVersion();
    UInt16 getFragmentLength();
    ContentType getType();
}
