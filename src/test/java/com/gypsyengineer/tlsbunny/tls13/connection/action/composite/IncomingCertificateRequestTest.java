package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingCertificateRequest;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoHandshake;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSCiphertext;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.tls13.crypto.AEAD.Method.aes_128_gcm;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static org.junit.Assert.assertArrayEquals;

public class IncomingCertificateRequestTest {

    @Test
    public void basic() throws Exception {
        Context context = context();

        byte[] expected_request_context = new byte[10];

        GeneratingCertificateRequest gcr = new GeneratingCertificateRequest();
        gcr.set(context);
        gcr.context(expected_request_context);
        gcr.signatures(SignatureScheme.ecdsa_secp521r1_sha512);

        ByteBuffer buffer = gcr.run().out();

        WrappingIntoHandshake wih = new WrappingIntoHandshake();
        wih.type(HandshakeType.certificate_request);
        wih.set(context);
        wih.in(buffer);

        buffer = wih.run().out();

        WrappingIntoTLSCiphertext witc = new WrappingIntoTLSCiphertext(Phase.handshake);
        witc.type(handshake);
        witc.set(context);
        witc.in(buffer);

        buffer = witc.run().out();

        IncomingCertificateRequest icr = new IncomingCertificateRequest();
        icr.set(context);
        icr.in(buffer);

        icr.run();

        byte[] actual_request_context = context.certificateRequestContext().bytes();
        assertArrayEquals(expected_request_context, actual_request_context);
    }

    @Test(expected = ActionFailed.class)
    public void notCertificateRequest() throws Exception {
        Context context = context();

        byte[] expected_request_context = new byte[10];

        GeneratingCertificateRequest gcr = new GeneratingCertificateRequest();
        gcr.set(context);
        gcr.context(expected_request_context);
        gcr.signatures(SignatureScheme.ecdsa_secp521r1_sha512);

        ByteBuffer buffer = gcr.run().out();

        WrappingIntoHandshake wih = new WrappingIntoHandshake();
        wih.type(HandshakeType.client_hello);
        wih.set(context);
        wih.in(buffer);

        buffer = wih.run().out();

        WrappingIntoTLSCiphertext witc = new WrappingIntoTLSCiphertext(Phase.handshake);
        witc.type(handshake);
        witc.set(context);
        witc.in(buffer);

        buffer = witc.run().out();

        IncomingCertificateRequest icr = new IncomingCertificateRequest();
        icr.set(context);
        icr.in(buffer);

        icr.run();
    }

    @Test(expected = IOException.class)
    public void noSignatures() throws Exception {
        Context context = context();

        byte[] expected_request_context = new byte[10];

        GeneratingCertificateRequest gcr = new GeneratingCertificateRequest();
        gcr.set(context);
        gcr.context(expected_request_context);

        ByteBuffer buffer = gcr.run().out();

        WrappingIntoHandshake wih = new WrappingIntoHandshake();
        wih.type(HandshakeType.certificate_request);
        wih.set(context);
        wih.in(buffer);

        buffer = wih.run().out();

        WrappingIntoTLSCiphertext witc = new WrappingIntoTLSCiphertext(Phase.handshake);
        witc.type(handshake);
        witc.set(context);
        witc.in(buffer);

        buffer = witc.run().out();

        IncomingCertificateRequest icr = new IncomingCertificateRequest();
        icr.set(context);
        icr.in(buffer);

        icr.run();
    }

    private static Context context() throws AEADException {
        Context context = new Context();
        context.set(StructFactory.getDefault());

        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        AEAD encryptor = AEAD.createEncryptor(aes_128_gcm, key, iv);
        AEAD decryptor = AEAD.createDecryptor(aes_128_gcm, key, iv);
        context.handshakeEncryptor(encryptor);
        context.handshakeDecryptor(decryptor);

        return context;
    }
}
