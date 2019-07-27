package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoHandshake;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSCiphertext;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.tls13.crypto.AEAD.Method.aes_128_gcm;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static org.junit.Assert.assertArrayEquals;

public class IncomingEncryptedHandshakeDataTest {

    @Test(expected = ActionFailed.class)
    public void notEncrypted() throws Exception {
        Context context = context();

        ByteBuffer buffer = new WrappingIntoTLSPlaintexts()
                .type(alert)
                .set(context)

                .in(ByteBuffer.wrap(new byte[10]))
                .run()
                .out();

        new IncomingEncryptedHandshakeData()
                .set(context)

                .in(buffer)
                .run();
    }

    @Test
    public void encrypted() throws Exception {
        Context context = context();

        ByteBuffer buffer = new WrappingIntoHandshake()
                .type(HandshakeType.client_hello)
                .set(context)

                .in(new byte[]{1, 2, 3})
                .run()
                .out();

        buffer = new WrappingIntoTLSCiphertext(Phase.handshake)
                .type(handshake)
                .set(context)

                .in(buffer)
                .run()
                .out();

        IncomingEncryptedHandshakeData ia = new IncomingEncryptedHandshakeData()
                .set(context)

                .in(buffer)
                .run();

        assertArrayEquals(
                new byte[]{
                        1,          // message type == client_hello
                        0, 0, 3,    // encoded length (uint24)
                        1, 2, 3     // body
                },
                ia.out().array());
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
