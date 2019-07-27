package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateStatusType;
import com.gypsyengineer.tlsbunny.tls13.struct.OCSPStatusRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.ResponderID;
import org.junit.Test;

import java.io.IOException;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertArrayEquals;

public class CertificateStatusRequestImplTest {

    @Test
    public void encoding() throws IOException {
        OCSPStatusRequestImpl ocspStatusRequest = new OCSPStatusRequestImpl(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                Vector.wrap(OCSPStatusRequest.extensions_encoding_length));

        CertificateStatusRequestImpl certificateStatusRequest = new CertificateStatusRequestImpl(
                CertificateStatusType.ocsp, ocspStatusRequest);

        assertEquals(
                CertificateStatusType.encoding_length + ocspStatusRequest.encodingLength(),
                certificateStatusRequest.encodingLength());

        assertEquals(
                certificateStatusRequest.encodingLength(),
                certificateStatusRequest.encoding().length);
    }

    @Test
    public void get() {
        OCSPStatusRequestImpl ocspStatusRequest = new OCSPStatusRequestImpl(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                Vector.wrap(OCSPStatusRequest.extensions_encoding_length));

        CertificateStatusRequestImpl certificateStatusRequest = new CertificateStatusRequestImpl(
                CertificateStatusType.ocsp, ocspStatusRequest);

        assertEquals(
                new OCSPStatusRequestImpl(
                        Vector.wrap(
                                OCSPStatusRequest.responder_id_list_encoding_length,
                                new ResponderIDImpl(
                                        Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                        Vector.wrap(OCSPStatusRequest.extensions_encoding_length)),
                certificateStatusRequest.getRequest()
        );

        assertEquals(
                CertificateStatusType.ocsp,
                certificateStatusRequest.getCertificateStatusType());
    }

    @Test
    public void copy() throws IOException {
        OCSPStatusRequestImpl ocspStatusRequest = new OCSPStatusRequestImpl(
                Vector.wrap(
                        OCSPStatusRequest.responder_id_list_encoding_length,
                        new ResponderIDImpl(
                                Vector.wrap(ResponderID.length_bytes, new byte[8]))),
                Vector.wrap(OCSPStatusRequest.extensions_encoding_length));

        CertificateStatusRequestImpl certificateStatusRequest = new CertificateStatusRequestImpl(
                CertificateStatusType.ocsp, ocspStatusRequest);

        CertificateStatusRequestImpl clone = certificateStatusRequest.copy();

        assertEquals(clone, certificateStatusRequest);
        assertEquals(clone.hashCode(), certificateStatusRequest.hashCode());
        assertArrayEquals(clone.encoding(), certificateStatusRequest.encoding());
    }

}
