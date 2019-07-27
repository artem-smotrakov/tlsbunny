package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingAlert;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSCiphertext;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.output.Output;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.tls13.crypto.AEAD.Method.aes_128_gcm;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class IncomingAlertTest {

    @Test
    public void notEncrypted()
            throws IOException, ActionFailed, AEADException, NegotiatorException {

        try (Output output = Output.standard()) {
            Context context = context();

            ByteBuffer buffer = new GeneratingAlert()
                    .level(AlertLevel.fatal)
                    .description(AlertDescription.handshake_failure)
                    .set(context)
                    .set(output)
                    .run()
                    .out();

            buffer = new WrappingIntoTLSPlaintexts()
                    .type(alert)
                    .set(context)
                    .set(output)
                    .in(buffer)
                    .run()
                    .out();

            IncomingAlert ia = new IncomingAlert()
                    .set(context)
                    .set(output)
                    .in(buffer)
                    .run();

            output.info(ia.name());

            Alert alert = context.getAlert();
            assertNotNull(alert);
            assertEquals(AlertLevel.fatal, alert.getLevel());
            assertEquals(AlertDescription.handshake_failure, alert.getDescription());
        }
    }

    @Test
    public void encrypted()
            throws IOException, ActionFailed, AEADException, NegotiatorException {

        try (Output output = Output.standard()) {
            Context context = context();

            ByteBuffer buffer = new GeneratingAlert()
                    .level(AlertLevel.warning)
                    .description(AlertDescription.unknown_ca)
                    .set(context)
                    .set(output)
                    .run()
                    .out();

            buffer = new WrappingIntoTLSCiphertext(Phase.application_data)
                    .type(alert)
                    .set(context)
                    .set(output)
                    .in(buffer)
                    .run()
                    .out();

            IncomingAlert ia = new IncomingAlert()
                    .set(context)
                    .set(output)
                    .in(buffer)
                    .run();

            output.info(ia.name());

            Alert alert = context.getAlert();
            assertNotNull(alert);
            assertEquals(AlertLevel.warning, alert.getLevel());
            assertEquals(AlertDescription.unknown_ca, alert.getDescription());
        }
    }

    private static Context context() throws AEADException {
        Context context = new Context();
        context.set(StructFactory.getDefault());

        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        AEAD encryptor = AEAD.createEncryptor(aes_128_gcm, key, iv);
        AEAD decryptor = AEAD.createDecryptor(aes_128_gcm, key, iv);
        context.applicationDataEncryptor(encryptor);
        context.applicationDataDecryptor(decryptor);

        return context;
    }
}
