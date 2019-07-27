package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface OCSPStatusRequest extends Struct {

    int responder_id_list_encoding_length = 2;
    int extensions_encoding_length = 2;

    Vector<ResponderID> getResponderIdList();
    Vector<Byte> getExtensions();
}
