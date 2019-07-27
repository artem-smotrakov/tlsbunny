package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.output.Output;
import org.junit.Test;

import java.nio.ByteBuffer;

import static junit.framework.TestCase.assertEquals;

public class PreservingEncryptedApplicationDataTest {

    @Test
    public void main() {
        try (Output output = Output.standard()) {
            PreservingEncryptedApplicationData action
                    = new PreservingEncryptedApplicationData();
            action.set(output);
            action.in(new byte[] {1, 2, 3});
            action.run();

            output.info(action.name());

            assertEquals(ByteBuffer.wrap(new byte[] {1, 2, 3}), action.applicationData());
        }
    }
}
