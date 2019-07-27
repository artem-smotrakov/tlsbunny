package com.gypsyengineer.tlsbunny.tls13.connection.action;

import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import java.nio.ByteBuffer;

import static org.junit.Assert.assertNotNull;

public class CCSTest {

    @Test
    public void generateAndParse() throws Exception {
        Context context = new Context();
        context.set(StructFactory.getDefault());

        ByteBuffer buffer = new OutgoingChangeCipherSpec()
                .set(ChangeCipherSpec.valid_value)
                .set(context)
                .run()
                .out();
        assertNotNull(buffer);

        new IncomingChangeCipherSpec()
                .expect(ChangeCipherSpec.valid_value)
                .set(context)
                .in(buffer)
                .run();
    }
}
