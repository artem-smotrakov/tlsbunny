package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;


import org.junit.Test;

import java.nio.ByteBuffer;

import static junit.framework.TestCase.assertEquals;

public class PreservingEncryptedApplicationDataTest {

    @Test
    public void main() {
        PreservingEncryptedApplicationData action
                = new PreservingEncryptedApplicationData();
        action.in(new byte[]{1, 2, 3});
        action.run();

        assertEquals(ByteBuffer.wrap(new byte[]{1, 2, 3}), action.applicationData());
    }
}
