package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Condition;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.server.Server;
import com.gypsyengineer.tlsbunny.tls13.struct.NewSessionTicket;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

import java.util.List;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingClientHello.generatingClientHello;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoHandshake.wrappingIntoHandshake;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts.wrappingIntoTLSPlaintexts;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class HttpsClientWithSessionResumption extends AbstractClient {

    public static HttpsClientWithSessionResumption from(Client client) {
        return new HttpsClientWithSessionResumption(client);
    }

    private final Client client;

    private HttpsClientWithSessionResumption(Client client) {
        Objects.requireNonNull(client, "Hey! Client can't be null!");
        this.client = client;
    }

    @Override
    protected Client connectImpl() throws Exception {
        client.connect();

        // TODO: extract this to a check
        Engine[] engines = client.engines();
        if (engines.length == 0) {
            throw whatTheHell("Hey! Client didn't return any engine!");
        }
        if (engines.length > 1) {
            throw whatTheHell("Hey! Client returned too many engines!");
        }

        List<NewSessionTicket> tickets = engines[0].context().sessionTickets();
        if (tickets.isEmpty()) {
            throw whatTheHell("Hey! No tickets received!");
        }
        NewSessionTicket ticket = tickets.get(0);

        // TODO: make sure that the same groups, key exchange algorithms, etc are used
        //       HttpsClient should probably be configurable with these parameters

        Engine engine = Engine.init()
                .set(host, port)
                .set(factory)
                .set(negotiator)

                .run(generatingClientHello()
                        .use(ticket))
                .run(wrappingIntoHandshake()
                        .type(client_hello)
                        .update(Context.Element.first_client_hello))
                .run(wrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12))
                .send(OutgoingData::new)

                .until(Condition::serverDone)
                .receive(IncomingMessages::fromServer)

                .run(GeneratingFinished::new)
                .run(wrappingIntoHandshake()
                        .type(finished)
                        .update(Context.Element.client_finished))
                .run(WrappingHandshakeDataIntoTLSCiphertext::new)
                .send(OutgoingData::new)

                .run(PreparingHttpGetRequest::new)
                .run(WrappingApplicationDataIntoTLSCiphertext::new)
                .send(OutgoingData::new)

                .until(Condition::applicationDataReceived)
                .receive(IncomingMessages::fromServer);

        super.engines.add(engine);

        engine.run().require(checks);

        return this;
    }

    @Override
    public AbstractClient to(Server server) {
        client.to(server);
        return super.to(server);
    }

    @Override
    public AbstractClient to(int port) {
        client.to(port);
        return super.to(port);
    }

    @Override
    public AbstractClient to(String host) {
        client.to(host);
        return super.to(host);
    }

    @Override
    public Client set(StructFactory factory) {
        client.set(factory);
        return super.set(factory);
    }

    @Override
    public Client set(Negotiator negotiator) {
        client.set(negotiator);
        return super.set(negotiator);
    }

    @Override
    public Client set(Check... checks) {
        client.set(checks);
        return super.set(checks);
    }

    @Override
    public Client set(Analyzer analyzer) {
        client.set(analyzer);
        return super.set(analyzer);
    }

    @Override
    public Client apply(Analyzer analyzer) {
        client.apply(analyzer);
        return super.apply(analyzer);
    }
}
