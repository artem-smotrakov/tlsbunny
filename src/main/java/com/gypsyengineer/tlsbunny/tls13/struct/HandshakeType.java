package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface HandshakeType extends Struct {

    int encoding_length = 1;
    
    HandshakeType certificate = StructFactory.getDefault().createHandshakeType(11);
    HandshakeType certificate_request = StructFactory.getDefault().createHandshakeType(13);
    HandshakeType certificate_verify = StructFactory.getDefault().createHandshakeType(15);
    HandshakeType client_hello = StructFactory.getDefault().createHandshakeType(1);
    HandshakeType encrypted_extensions = StructFactory.getDefault().createHandshakeType(8);
    HandshakeType end_of_early_data = StructFactory.getDefault().createHandshakeType(5);
    HandshakeType finished = StructFactory.getDefault().createHandshakeType(20);
    HandshakeType hello_retry_request = StructFactory.getDefault().createHandshakeType(6);
    HandshakeType key_update = StructFactory.getDefault().createHandshakeType(24);
    HandshakeType message_hash = StructFactory.getDefault().createHandshakeType(254);
    HandshakeType new_session_ticket = StructFactory.getDefault().createHandshakeType(4);
    HandshakeType server_hello = StructFactory.getDefault().createHandshakeType(2);

    int getValue();
}
