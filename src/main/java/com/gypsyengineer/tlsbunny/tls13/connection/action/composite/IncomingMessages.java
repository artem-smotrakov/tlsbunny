package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class IncomingMessages extends AbstractAction<IncomingMessages> {

    private Side side;

    public IncomingMessages(Side side) {
        this.side = side;
    }

    @Override
    public String name() {
        return String.format("incoming messages (%s)", side);
    }

    public IncomingMessages side(Side side) {
        this.side = side;
        return this;
    }

    public IncomingMessages server() {
        side = Side.server;
        return this;
    }

    public IncomingMessages client() {
        side = Side.client;
        return this;
    }

    @Override
    public IncomingMessages run() throws AEADException, ActionFailed,
            IOException, NegotiatorException {

        while (in.remaining() > 0) {
            try {
                runImpl();
            } finally {
                output.flush();
            }
        }

        return this;
    }

    private void runImpl()
            throws ActionFailed, IOException, AEADException, NegotiatorException {

        TLSPlaintext tlsPlaintext
                = new ProcessingTLSPlaintext()
                        .set(output)
                        .set(context)
                        .in(in)
                        .run()
                        .tlsPlaintext();

        if (tlsPlaintext.containsChangeCipherSpec()) {
            processChangeCipherSpec(tlsPlaintext);
            return;
        }

        if (tlsPlaintext.containsAlert()) {
            processAlert(tlsPlaintext);
            return;
        }

        ContentType type;
        ByteBuffer content;

        if (expectEncryptedHandshakeData()) {
            TLSInnerPlaintext tlsInnerPlaintext =
                    new ProcessingTLSCiphertext(Phase.handshake)
                            .set(output)
                            .set(context)
                            .set(tlsPlaintext)
                            .run()
                            .tlsInnerPlaintext();

            type = tlsInnerPlaintext.getType();
            content = ByteBuffer.wrap(tlsInnerPlaintext.getContent());
        } else if (expectEncryptedApplicationData()) {
            if (canDecryptApplicationData()) {
                TLSInnerPlaintext tlsInnerPlaintext =
                        new ProcessingTLSCiphertext(Phase.application_data)
                                .set(output)
                                .set(context)
                                .set(tlsPlaintext)
                                .run()
                                .tlsInnerPlaintext();

                type = tlsInnerPlaintext.getType();
                content = ByteBuffer.wrap(tlsInnerPlaintext.getContent());
            } else {
                new PreservingEncryptedApplicationData()
                        .set(output)
                        .set(context)
                        .in(tlsPlaintext.getFragment())
                        .run();
                return;
            }
        } else {
            type = tlsPlaintext.getType();
            content = ByteBuffer.wrap(tlsPlaintext.getFragment());
        }

        if (ContentType.handshake.equals(type)) {
            processHandshake(content);
            return;
        }

        if (ContentType.alert.equals(type)) {
            processAlert(content);
            return;
        }

        if (ContentType.application_data.equals(type)) {
            processApplicationData(content);
            return;
        }

        throw whatTheHell("unexpected content type!");
    }

    private boolean expectEncryptedHandshakeData() {
        if (side == Side.client) {
            return context.hasServerHello() && !context.receivedServerFinished();
        }

        if (side == Side.server) {
            return context.hasFirstClientHello() && !context.receivedClientFinished();
        }

        throw whatTheHell("unexpected side: %s", side);
    }

    private boolean expectEncryptedApplicationData() {
        if (side == Side.client) {
            return context.receivedServerFinished();
        }

        if (side == Side.server) {
            return context.receivedClientFinished();
        }

        throw whatTheHell("unexpected side: %s", side);
    }

    private boolean canDecryptApplicationData() {
        return context.applicationDataDecryptor() != null;
    }

    private void processHandshake(ByteBuffer buffer)
            throws ActionFailed, NegotiatorException, IOException, AEADException {

        while (buffer.remaining() > 0) {
            Handshake handshake =
                    new ProcessingHandshake()
                            .set(output)
                            .set(context)
                            .in(buffer)
                            .run()
                            .handshake();

            if (handshake.containsClientHello()) {
                processClientHello(handshake);
                continue;
            }

            if (handshake.containsServerHello()) {
                processServerHello(handshake);
                continue;
            }

            if (handshake.containsHelloRetryRequest()) {
                processHelloRetryRequest(handshake);
                continue;
            }

            if (handshake.containsEncryptedExtensions()) {
                processEncryptedExtensions(handshake);
                continue;
            }

            if (handshake.containsCertificateRequest()) {
                processCertificateRequest(handshake);
                continue;
            }

            if (handshake.containsCertificate()) {
                processCertificate(handshake);
                continue;
            }

            if (handshake.containsCertificateVerify()) {
                processCertificateVerify(handshake);
                continue;
            }

            if (handshake.containsFinished()) {
                processFinished(handshake);
                continue;
            }

            if (handshake.containsNewSessionTicket()) {
                processNewSessionTicket(handshake);
                continue;
            }

            throw whatTheHell("unexpected handshake message!");
        }
    }

    private void processChangeCipherSpec(TLSPlaintext tlsPlaintext) throws ActionFailed {
        processChangeCipherSpec(ByteBuffer.wrap(tlsPlaintext.getFragment()));
    }

    private void processChangeCipherSpec(ByteBuffer buffer) throws ActionFailed {
        new ProcessingChangeCipherSpec()
                .set(output)
                .set(context)
                .in(buffer)
                .run();
    }

    private void processAlert(TLSPlaintext tlsPlaintext) {
        processAlert(ByteBuffer.wrap(tlsPlaintext.getFragment()));
    }

    private void processAlert(ByteBuffer buffer) {
        new ProcessingAlert()
                .set(output)
                .set(context)
                .in(buffer)
                .run();
    }

    private void processApplicationData(ByteBuffer buffer) {
        context.addApplicationData(buffer.array());
        new PrintingData()
                .set(output)
                .set(context)
                .in(buffer)
                .run();
    }

    private void processClientHello(Handshake handshake) throws ActionFailed {
        new ProcessingClientHello()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        if (context.hasFirstClientHello() && context.hasSecondClientHello()) {
            throw new ActionFailed(
                    "what the hell? we have already received two client hellos!");
        }

        if (!context.hasFirstClientHello()) {
            context.setFirstClientHello(handshake);
        } else {
            context.setSecondClientHello(handshake);
        }
    }

    private void processServerHello(Handshake handshake)
            throws IOException, AEADException, NegotiatorException {

        new ProcessingServerHello()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        context.setServerHello(handshake);

        new NegotiatingClientDHSecret()
                .set(output)
                .set(context)
                .run();

        new ComputingHandshakeTrafficKeys()
                .set(output)
                .set(context)
                .side(side)
                .run();
    }

    private void processHelloRetryRequest(Handshake handshake) {
        throw new UnsupportedOperationException("no message processing for you!");
    }

    private void processEncryptedExtensions(Handshake handshake) {
        new ProcessingEncryptedExtensions()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        context.setEncryptedExtensions(handshake);
    }

    private void processCertificateRequest(Handshake handshake) {
        new ProcessingCertificateRequest()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        context.setServerCertificateRequest(handshake);
    }

    private void processCertificate(Handshake handshake) {
        new ProcessingCertificate()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        if (side == Side.client) {
            context.setServerCertificate(handshake);
        }

        if (side == Side.server) {
            context.setClientCertificate(handshake);
        }
    }

    private void processCertificateVerify(Handshake handshake) {
        new ProcessingCertificateVerify()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        if (side == Side.client) {
            context.setServerCertificateVerify(handshake);
        }

        if (side == Side.server) {
            context.setClientCertificateVerify(handshake);
        }
    }

    private void processFinished(Handshake handshake)
            throws IOException, ActionFailed, AEADException {

        if (side == Side.client) {
            context.setServerFinished(handshake);
        }

        new ProcessingFinished(side)
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();

        new ComputingApplicationTrafficKeys()
                .set(output)
                .set(context)
                .side(side)
                .run();

        if (side == Side.server) {
            context.setClientFinished(handshake);
        }

        if (side == Side.client) {
            context.setServerFinished(handshake);
        }
    }

    private void processNewSessionTicket(Handshake handshake) throws IOException {
        new ProcessingNewSessionTicket()
                .set(output)
                .set(context)
                .in(handshake.getBody())
                .run();
    }

}
