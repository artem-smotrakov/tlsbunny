package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface Extension extends Struct {

    int extension_data_length_bytes = 2;

    Vector<Byte> extensionData();
    ExtensionType extensionType();

    Extension extensionData(Vector<Byte> data);
    Extension extensionType(ExtensionType type);
}
