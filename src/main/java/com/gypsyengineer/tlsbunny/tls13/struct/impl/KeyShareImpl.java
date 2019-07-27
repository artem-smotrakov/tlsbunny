package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShare;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class KeyShareImpl implements KeyShare {
    
    public static class ClientHelloImpl extends KeyShareImpl implements ClientHello {

        private Vector<KeyShareEntry> client_shares;

        ClientHelloImpl() {
            this(Vector.wrap(length_bytes));
        }

        public ClientHelloImpl(Vector<KeyShareEntry> client_shares) {
            this.client_shares = client_shares;
        }

        @Override
        public int encodingLength() {
            return client_shares.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return client_shares.encoding();
        }

        @Override
        public ClientHelloImpl copy() {
            return new ClientHelloImpl((Vector<KeyShareEntry>) client_shares.copy());
        }

        @Override
        public Vector<KeyShareEntry> getClientShares() {
            return client_shares;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            ClientHelloImpl that = (ClientHelloImpl) o;
            return Objects.equals(client_shares, that.client_shares);
        }

        @Override
        public int hashCode() {
            return Objects.hash(client_shares);
        }

        @Override
        public boolean composite() {
            return true;
        }

        @Override
        public int total() {
            return 1;
        }

        @Override
        public Struct element(int index) {
            switch (index) {
                case 0:
                    return client_shares;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public void element(int index, Struct element) {
            if (element == null) {
                throw whatTheHell("element can't be null!");
            }
            switch (index) {
                case 0:
                    client_shares = cast(element, Vector.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }
    }
    
    public static class ServerHelloImpl extends KeyShareImpl implements ServerHello {

        private KeyShareEntry server_share;

        ServerHelloImpl(KeyShareEntry server_share) {
            this.server_share = server_share;
        }

        @Override
        public KeyShareEntry getServerShare() {
            return server_share;
        }

        @Override
        public int encodingLength() {
            return server_share.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return server_share.encoding();
        }

        @Override
        public ServerHelloImpl copy() {
            return new ServerHelloImpl((KeyShareEntry) server_share.copy());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            ServerHelloImpl that = (ServerHelloImpl) o;
            return Objects.equals(server_share, that.server_share);
        }

        @Override
        public int hashCode() {
            return Objects.hash(server_share);
        }

        @Override
        public boolean composite() {
            return true;
        }

        @Override
        public int total() {
            return 1;
        }

        @Override
        public Struct element(int index) {
            switch (index) {
                case 0:
                    return server_share;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public void element(int index, Struct element) {
            if (element == null) {
                throw whatTheHell("element can't be null!");
            }
            switch (index) {
                case 0:
                    server_share = cast(element, KeyShareEntry.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }
    }
    
    public static class HelloRetryRequestImpl extends KeyShareImpl 
            implements HelloRetryRequest {

        private NamedGroup selected_group;

        HelloRetryRequestImpl(NamedGroup selected_group) {
            this.selected_group = selected_group;
        }

        @Override
        public NamedGroup getSelectedGroup() {
            return selected_group;
        }

        @Override
        public int encodingLength() {
            return selected_group.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return selected_group.encoding();
        }

        @Override
        public HelloRetryRequestImpl copy() {
            return new HelloRetryRequestImpl((NamedGroup) selected_group.copy());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            HelloRetryRequestImpl that = (HelloRetryRequestImpl) o;
            return Objects.equals(selected_group, that.selected_group);
        }

        @Override
        public int hashCode() {
            return Objects.hash(selected_group);
        }

        @Override
        public boolean composite() {
            return true;
        }

        @Override
        public int total() {
            return 1;
        }

        @Override
        public Struct element(int index) {
            switch (index) {
                case 0:
                    return selected_group;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public void element(int index, Struct element) {
            if (element == null) {
                throw whatTheHell("element can't be null!");
            }
            switch (index) {
                case 0:
                    selected_group = cast(element, NamedGroup.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }
    }
}
