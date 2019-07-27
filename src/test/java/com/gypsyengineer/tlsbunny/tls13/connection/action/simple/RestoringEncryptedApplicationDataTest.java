package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import org.junit.Test;

import java.nio.ByteBuffer;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNull;

public class RestoringEncryptedApplicationDataTest {

    @Test
    public void main() {
        RestoringEncryptedApplicationData action
                = new RestoringEncryptedApplicationData();

        action.applicationData(ByteBuffer.wrap(new byte[0]));
        action.run();
        assertNull(action.out());

        action.applicationData(ByteBuffer.wrap(new byte[]{1, 2, 3}));
        action.run();
        assertEquals(ByteBuffer.wrap(new byte[]{1, 2, 3}), action.out());
    }
}
