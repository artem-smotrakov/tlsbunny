package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingMainServerFlight;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.AlertCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.ECDHENegotiator;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import com.gypsyengineer.tlsbunny.utils.Utils;
import org.junit.Test;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SendAlertAfterHelloTest {

    @Test
    public void test() throws Exception {
        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        Config serverConfig = SystemPropertiesConfig.load();
        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl()
                        .set(serverConfig)
                        .set(serverOutput))
                .set(serverConfig)
                .set(serverOutput)
                .set(new AlertCheck())
                .maxConnections(1);

        SendAlertAfterHello client = new SendAlertAfterHello();

        try (server; clientOutput; serverOutput) {
            server.start();

            Config clientConfig = SystemPropertiesConfig.load().port(server.port());
            client.set(clientConfig).set(clientOutput);

            try (client) {
                client.connect();
            }
        }

        Utils.waitStop(server);

        assertEquals(1, server.engines().length);
        assertNotNull(server.engines()[0].context().getAlert());
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        public EngineFactoryImpl set(Config config) {
            this.config = config;
            return this;
        }

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)
                    .set(output)
                    .set(ECDHENegotiator.create(NamedGroup.secp256r1, StructFactory.getDefault()))

                    .receive(new IncomingData())

                    // process ClientHello
                    .loop(context -> !context.hasFirstClientHello() && !context.hasAlert())
                        .receive(() -> new IncomingMessages(Side.server))

                    // send messages
                    .send(new OutgoingMainServerFlight().apply(config))

                    // receive Finished and application data
                    .loop(context -> !context.receivedApplicationData() && !context.hasAlert())
                        .receive(() -> new IncomingMessages(Side.server))

                    // send application data
                    .run(new PreparingHttpResponse())
                    .run(new WrappingApplicationDataIntoTLSCiphertext())
                    .send(new OutgoingData());
        }
    }
}
