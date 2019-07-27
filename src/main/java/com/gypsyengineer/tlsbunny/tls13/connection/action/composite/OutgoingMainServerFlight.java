package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.utils.Config;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.rsa_pkcs1_sha256;

public class OutgoingMainServerFlight extends AbstractAction<OutgoingMainServerFlight> {

    private String serverCertificate;
    private String serverKey;

    private boolean clientAuthEnabled = false;

    private ByteArrayOutputStream os;

    public OutgoingMainServerFlight apply(Config config) {
        serverCertificate = config.serverCertificate();
        serverKey = config.serverKey();
        return this;
    }

    public OutgoingMainServerFlight clientAuth() {
        clientAuthEnabled = true;
        return this;
    }

    @Override
    public String name() {
        return "outgoing server messages";
    }

    @Override
    public OutgoingMainServerFlight run() throws ActionFailed, AEADException,
            NegotiatorException, IOException {

        try {
            runImpl();
        } finally {
            output.flush();
        }

        return this;
    }

    private void store(ByteBuffer buffer) throws IOException {
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        os.write(bytes);
    }

    private void runImpl()
            throws ActionFailed, IOException, AEADException, NegotiatorException {

        ByteBuffer buffer;
        os = new ByteArrayOutputStream();

        buffer = new GeneratingServerHello()
                .supportedVersion(TLSv13)
                .group(secp256r1)
                .signatureScheme(ecdsa_secp256r1_sha256)
                .keyShareEntry(context -> context.negotiator().createKeyShareEntry())
                .set(output)
                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(server_hello)
                .updateContext(Context.Element.server_hello)
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingIntoTLSPlaintexts()
                .type(handshake)
                .version(TLSv12)
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        buffer = new OutgoingChangeCipherSpec()
                .set(output)
                .set(context)
                .run()
                .out();
        store(buffer);

        new NegotiatingServerDHSecret()
                .set(output)
                .set(context)
                .run();

        new ComputingHandshakeTrafficKeys()
                .server()
                .set(output)
                .set(context)
                .run();

        buffer = new GeneratingEncryptedExtensions()
                .set(output)
                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(encrypted_extensions)
                .updateContext(Context.Element.encrypted_extensions)
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        if (clientAuthEnabled) {
            buffer = new GeneratingCertificateRequest()
                    .signatures(rsa_pkcs1_sha256)
                    .set(output)
                    .set(context)
                    .run()
                    .out();
            buffer = new WrappingIntoHandshake()
                    .type(certificate_request)
                    .updateContext(Context.Element.server_certificate_request)
                    .set(output)
                    .set(context)
                    .in(buffer)
                    .run()
                    .out();
            buffer = new WrappingHandshakeDataIntoTLSCiphertext()
                    .set(output)
                    .set(context)
                    .in(buffer)
                    .run()
                    .out();
            store(buffer);
        }

        buffer = new GeneratingCertificate()
                .certificate(serverCertificate)
                .set(output)
                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(certificate)
                .updateContext(Context.Element.server_certificate)
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        buffer = new GeneratingCertificateVerify()
                .server()
                .key(serverKey)
                .set(output)
                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(certificate_verify)
                .updateContext(Context.Element.server_certificate_verify)
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        buffer = new GeneratingFinished(Side.server)
                .set(output)
                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(finished)
                .updateContext(Context.Element.server_finished)
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()
                .set(output)
                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        out = ByteBuffer.wrap(os.toByteArray());
    }
}
