package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface CompressionMethod extends Struct {

    int encoding_length = 1;

    CompressionMethod None = StructFactory.getDefault().createCompressionMethod(0);

    int code();
}
