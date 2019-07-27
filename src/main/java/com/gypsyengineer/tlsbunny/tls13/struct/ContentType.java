package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface ContentType extends Struct {

    int encoding_length = 1;

    ContentType invalid = StructFactory.getDefault().createContentType(0);
    ContentType change_cipher_spec = StructFactory.getDefault().createContentType(20);
    ContentType alert = StructFactory.getDefault().createContentType(21);
    ContentType handshake = StructFactory.getDefault().createContentType(22);
    ContentType application_data = StructFactory.getDefault().createContentType(23);

    int getCode();
    boolean isAlert();
    boolean isApplicationData();
    boolean isHandshake();
    boolean isChangeCipherSpec();
    boolean isInvalid();
}
