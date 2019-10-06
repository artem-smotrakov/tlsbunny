package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoExceptionCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoFatalAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

import java.util.List;

public class AnotherHttpsClient extends SingleConnectionClient {

    public static void main(String... args) throws Exception {
        try (AnotherHttpsClient client = new AnotherHttpsClient()) {
            client.set(StructFactory.getDefault()).connect();
        }
    }

    public AnotherHttpsClient() {
        checks = List.of(
                new NoFatalAlertCheck(),
                new SuccessCheck(),
                new NoExceptionCheck());
    }

    @Override
    protected Engine createEngine() throws Exception {
        return Engine.init()
                .target(host)
                .target(port)
                .set(factory)
                .set(negotiator)

                .send(new OutgoingClientHello())
                .send(new OutgoingChangeCipherSpec())
                .receive(new IncomingServerHello())
                .receive(new IncomingChangeCipherSpec())
                .receive(new IncomingEncryptedExtensions())
                .receive(new IncomingCertificate())
                .receive(new IncomingCertificateVerify())
                .receive(new IncomingFinished())
                .send(new OutgoingFinished())
                .send(new OutgoingHttpGetRequest())
                .receive(new IncomingApplicationData());
    }

}
