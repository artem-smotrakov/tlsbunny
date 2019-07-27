package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
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

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class ProcessingTLSPlaintextWithAlertTest {

    @Test
    public void basic()
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

            ProcessingTLSPlaintextWithAlert ia = new ProcessingTLSPlaintextWithAlert()
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
    public void notAlert()
            throws IOException, AEADException, NegotiatorException {

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
                    .type(handshake)
                    .set(context)
                    .set(output)
                    .in(buffer)
                    .run()
                    .out();

            new ProcessingTLSPlaintextWithAlert()
                    .set(context)
                    .set(output)
                    .in(buffer)
                    .run();

            fail("no expected exception was thrown!");
        } catch (ActionFailed e) {
            // good
        }
    }

    private static Context context() {
        Context context = new Context();
        context.set(StructFactory.getDefault());
        return context;
    }
}
