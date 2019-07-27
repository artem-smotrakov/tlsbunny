package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.output.Output;
import org.junit.Test;

import java.nio.ByteBuffer;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNull;

public class RestoringEncryptedApplicationDataTest {

    @Test
    public void main() {
        try (Output output = Output.standard()) {
            RestoringEncryptedApplicationData action
                    = new RestoringEncryptedApplicationData();
            action.set(output);
            output.info(action.name());

            action.applicationData(ByteBuffer.wrap(new byte[0]));
            action.run();
            assertNull(action.out());

            action.applicationData(ByteBuffer.wrap(new byte[] {1, 2, 3}));
            action.run();
            assertEquals(ByteBuffer.wrap(new byte[] {1, 2, 3}), action.out());
        }
    }
}
