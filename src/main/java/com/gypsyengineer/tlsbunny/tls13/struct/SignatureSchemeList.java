package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface SignatureSchemeList extends Struct {

    int length_bytes = 2;

    Vector<SignatureScheme> getSupportedSignatureAlgorithms();
}
