package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.client.ccs.InvalidCCS;
import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import com.gypsyengineer.tlsbunny.utils.WhatTheHell;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class InvalidCCSTest {

    @Test
    public void invalidParameters() {
        checkException(() -> new InvalidCCS().startWith(-1));
        checkException(() -> new InvalidCCS().startWith(256));
        checkException(() -> new InvalidCCS().endWith(-1));
        checkException(() -> new InvalidCCS().endWith(256));
        checkException(() -> new InvalidCCS().startWith(10).endWith(5).connect());
    }

    @Test
    public void run() throws Exception {
        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        Config serverConfig = SystemPropertiesConfig.load();

        InvalidCCS client = new InvalidCCS();

        int start = 10;
        int end = 15;
        int n = end - start + 1;

        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl()
                        .set(serverConfig)
                        .set(serverOutput))
                .set(serverConfig)
                .set(serverOutput)
                .maxConnections(n);

        try (client; server; clientOutput; serverOutput) {
            server.start();

            Config clientConfig = SystemPropertiesConfig.load().port(server.port());

            client.startWith(start).endWith(end)
                    .set(clientConfig).set(clientOutput)
                    .connect();
        }

        assertEquals(n, client.engines().length);
        for (Engine engine : client.engines()) {
            assertTrue(engine.context().getAlert() != null
                    || engine.exception() != null);
        }

        assertEquals(n, server.engines().length);
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

                    .receive(new IncomingData())

                    // process ClientHello
                    .run(new ProcessingTLSPlaintext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(client_hello)
                            .updateContext(Context.Element.first_client_hello))
                    .run(new ProcessingClientHello())

                    // receive an invalid CCS
                    .receive(new IncomingChangeCipherSpec())

                    // send an alert
                    .run(new GeneratingAlert()
                            .level(AlertLevel.fatal)
                            .description(AlertDescription.unexpected_message))
                    .run(new WrappingIntoTLSPlaintexts()
                            .version(TLSv12)
                            .type(alert))
                    .send(new OutgoingData());
        }
    }

    interface ExceptionTest {
        void run() throws Exception;
    }

    private static void checkException(ExceptionTest task) {
        try {
            task.run();
            fail("expected WhatTheHell exception");
        } catch (WhatTheHell e) {
            // good
        } catch (Exception e) {
            e.printStackTrace();
            fail("unexpected exception");
        }
    }
}
