package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.OCSPStatusRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.ResponderID;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.util.Objects;

public class OCSPStatusRequestImpl implements OCSPStatusRequest {

    private Vector<ResponderID> responder_id_list;
    private Vector<Byte> extensions;

    OCSPStatusRequestImpl(
            Vector<ResponderID> responder_id_list, Vector<Byte> extensions) {
        this.responder_id_list = responder_id_list;
        this.extensions = extensions;
    }

    @Override
    public Vector<ResponderID> getResponderIdList() {
        return responder_id_list;
    }

    @Override
    public Vector<Byte> getExtensions() {
        return extensions;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(responder_id_list, extensions);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(responder_id_list, extensions);
    }

    @Override
    public OCSPStatusRequestImpl copy() {
        return new OCSPStatusRequestImpl(
                (Vector<ResponderID>) responder_id_list.copy(),
                (Vector<Byte>) extensions.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OCSPStatusRequestImpl that = (OCSPStatusRequestImpl) o;
        return Objects.equals(responder_id_list, that.responder_id_list) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(responder_id_list, extensions);
    }
}
