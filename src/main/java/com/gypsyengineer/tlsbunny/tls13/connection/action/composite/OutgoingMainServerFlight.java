package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.rsa_pkcs1_sha256;

public class OutgoingMainServerFlight extends AbstractAction<OutgoingMainServerFlight> {

    private static final Logger logger = LogManager.getLogger(OutgoingMainServerFlight.class);

    private String serverCertificate;
    private String serverKey;
    private boolean clientAuthEnabled = false;
    private ByteArrayOutputStream os;

    public OutgoingMainServerFlight(String certificate, String key) {
        Objects.requireNonNull(certificate, "hey! certificate can't be null!");
        Objects.requireNonNull(key, "hey! key can't be null!");
        serverCertificate = certificate;
        serverKey = key;
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
    public OutgoingMainServerFlight run() throws ActionFailed, AEADException, NegotiatorException, IOException {
        runImpl();
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

                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(server_hello)
                .update(Context.Element.server_hello)

                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingIntoTLSPlaintexts()
                .type(handshake)
                .version(TLSv12)

                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        buffer = new OutgoingChangeCipherSpec()

                .set(context)
                .run()
                .out();
        store(buffer);

        new NegotiatingServerDHSecret()

                .set(context)
                .run();

        new ComputingHandshakeTrafficKeys()
                .server()

                .set(context)
                .run();

        buffer = new GeneratingEncryptedExtensions()

                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(encrypted_extensions)
                .update(Context.Element.encrypted_extensions)

                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()

                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        if (clientAuthEnabled) {
            buffer = new GeneratingCertificateRequest()
                    .signatures(rsa_pkcs1_sha256)

                    .set(context)
                    .run()
                    .out();
            buffer = new WrappingIntoHandshake()
                    .type(certificate_request)
                    .update(Context.Element.server_certificate_request)

                    .set(context)
                    .in(buffer)
                    .run()
                    .out();
            buffer = new WrappingHandshakeDataIntoTLSCiphertext()

                    .set(context)
                    .in(buffer)
                    .run()
                    .out();
            store(buffer);
        }

        buffer = new GeneratingCertificate()
                .certificate(serverCertificate)

                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(certificate)
                .update(Context.Element.server_certificate)

                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()

                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        buffer = new GeneratingCertificateVerify()
                .server()
                .key(serverKey)

                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(certificate_verify)
                .update(Context.Element.server_certificate_verify)

                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()

                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        buffer = new GeneratingFinished(Side.server)

                .set(context)
                .run()
                .out();
        buffer = new WrappingIntoHandshake()
                .type(finished)
                .update(Context.Element.server_finished)

                .set(context)
                .in(buffer)
                .run()
                .out();
        buffer = new WrappingHandshakeDataIntoTLSCiphertext()

                .set(context)
                .in(buffer)
                .run()
                .out();
        store(buffer);

        out = ByteBuffer.wrap(os.toByteArray());
    }
}
