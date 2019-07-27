package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.OCSPStatusRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.ResponderID;
import org.junit.Test;

import java.io.IOException;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertArrayEquals;

public class OCSPStatusRequestImplTest {

    @Test
    public void encoding() throws IOException {
        OCSPStatusRequestImpl request = new OCSPStatusRequestImpl(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                Vector.wrap(OCSPStatusRequest.extensions_encoding_length));

        assertEquals(OCSPStatusRequest.responder_id_list_encoding_length
                        + ResponderID.length_bytes + 8
                        + OCSPStatusRequest.extensions_encoding_length,
                request.encodingLength());

        assertEquals(request.encodingLength(), request.encoding().length);
    }

    @Test
    public void get() {
        OCSPStatusRequestImpl request = new OCSPStatusRequestImpl(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                Vector.wrap(
                        OCSPStatusRequest.extensions_encoding_length,
                        new byte[] {1, 2, 3}));

        assertEquals(
                Vector.wrap(
                        OCSPStatusRequest.extensions_encoding_length,
                        new byte[] {1, 2, 3}),
                request.getExtensions());

        assertEquals(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                request.getResponderIdList()
        );
    }

    @Test
    public void copy() throws IOException {
        OCSPStatusRequestImpl request = new OCSPStatusRequestImpl(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                Vector.wrap(OCSPStatusRequest.extensions_encoding_length));

        OCSPStatusRequest clone = request.copy();

        assertEquals(clone, request);
        assertEquals(clone.hashCode(), request.hashCode());
        assertArrayEquals(clone.encoding(), request.encoding());

        assertEquals(
                clone.getResponderIdList().first().content(),
                request.getResponderIdList().first().content());
    }
}
