package com.gypsyengineer.tlsbunny.tls13.connection.action;

import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingClientHello;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.ProcessingClientHello;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.ECDHENegotiator;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.output.Output;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ClientHelloTest {

    @Test
    public void generateAndParse() throws Exception {
        Context context = new Context();
        context.set(StructFactory.getDefault());
        context.set(ECDHENegotiator.create(
                NamedGroup.Secp.secp256r1, StructFactory.getDefault())
                    .strictValidation());

        try (Output output = Output.standard()) {
            ByteBuffer buffer = new GeneratingClientHello()
                    .supportedVersions(TLSv13)
                    .groups(secp256r1)
                    .signatureSchemes(ecdsa_secp256r1_sha256)
                    .keyShareEntries(c -> c.negotiator().createKeyShareEntry())
                    .set(context)
                    .set(output)
                    .run()
                    .out();
            assertNotNull(buffer);

            ClientHello secondHello = new ProcessingClientHello()
                    .set(context)
                    .in(buffer)
                    .set(output)
                    .run()
                    .get();

            buffer.flip();
            ClientHello firstHello = StructFactory.getDefault().parser().parseClientHello(buffer);
            assertNotNull(firstHello);

            assertArrayEquals(firstHello.encoding(), secondHello.encoding());
            assertEquals(firstHello, secondHello);
        }
    }

    @Test
    public void manyGroups() throws Exception {
        Context context = new Context();
        context.set(StructFactory.getDefault());
        context.set(ECDHENegotiator.create(
                NamedGroup.Secp.secp256r1, StructFactory.getDefault())
                    .strictValidation());

        int n = 30000;
        NamedGroup[] tooManyGroups = new NamedGroup[n];
        for (int i = 0; i < n; i++) {
            tooManyGroups[i] = secp256r1;
        }

        try (Output output = Output.standard()) {
            ByteBuffer buffer = new GeneratingClientHello()
                    .supportedVersions(TLSv13)
                    .groups(tooManyGroups)
                    .signatureSchemes(ecdsa_secp256r1_sha256)
                    .keyShareEntries(c -> c.negotiator().createKeyShareEntry())
                    .set(context)
                    .set(output)
                    .run()
                    .out();
            assertNotNull(buffer);

            ClientHello secondHello = new ProcessingClientHello()
                    .set(context)
                    .in(buffer)
                    .set(output)
                    .run()
                    .get();

            buffer.flip();
            ClientHello firstHello = StructFactory.getDefault().parser().parseClientHello(buffer);
            assertNotNull(firstHello);

            assertArrayEquals(firstHello.encoding(), secondHello.encoding());
            assertEquals(firstHello, secondHello);

            TLSPlaintext[] one = wrap(firstHello);
            TLSPlaintext[] two = wrap(secondHello);

            assertArrayEquals(one, two);
        }
    }

    private static TLSPlaintext[] wrap(ClientHello hello) throws IOException {
        StructFactory factory = StructFactory.getDefault();

        return factory.createTLSPlaintexts(
                ContentType.handshake,
                ProtocolVersion.TLSv12,
                factory.createHandshake(
                        HandshakeType.client_hello,
                        hello.encoding()).encoding());
    }
}
