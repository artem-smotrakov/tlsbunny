package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface UncompressedPointRepresentation extends Struct {

    byte[] getX();
    byte[] getY();
}
