package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls13.struct.OfferedPsks;
import com.gypsyengineer.tlsbunny.tls13.struct.PreSharedKeyExtension;

import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class PreSharedKeyExtensionImpl implements PreSharedKeyExtension {

    public static class ClientHelloImpl implements ClientHello {

        private OfferedPsks offeredPsks;

        ClientHelloImpl(OfferedPsks offeredPsks) {
            this.offeredPsks = offeredPsks;
        }

        @Override
        public OfferedPsks offeredPsks() {
            return offeredPsks;
        }

        @Override
        public int encodingLength() {
            return offeredPsks.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return offeredPsks.encoding();
        }

        @Override
        public Struct copy() {
            return new ClientHelloImpl(offeredPsks);
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
            if (index == 0) {
                return offeredPsks;
            }
            throw whatTheHell("incorrect index %d!", index);
        }

        @Override
        public void element(int index, Struct element) {
            if (index == 0) {
                offeredPsks = cast(element, OfferedPsks.class);
            }
            throw whatTheHell("incorrect index %d!", index);
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
            return Objects.equals(offeredPsks, that.offeredPsks);
        }

        @Override
        public int hashCode() {
            return Objects.hash(offeredPsks);
        }
    }

    public static class ServerHelloImpl implements ServerHello {

        private UInt16 selected_identity;

        ServerHelloImpl(UInt16 selected_identity) {
            this.selected_identity = selected_identity;
        }

        @Override
        public UInt16 selectedIdentity() {
            return selected_identity;
        }

        @Override
        public int encodingLength() {
            return selected_identity.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return selected_identity.encoding();
        }

        @Override
        public Struct copy() {
            return new ServerHelloImpl(selected_identity);
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
            if (index == 0) {
                return selected_identity;
            }
            throw whatTheHell("incorrect index %d!", index);
        }

        @Override
        public void element(int index, Struct element) {
            if (index == 0) {
                selected_identity = cast(element, UInt16.class);
            }
            throw whatTheHell("incorrect index %d!", index);
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
            return Objects.equals(selected_identity, that.selected_identity);
        }

        @Override
        public int hashCode() {
            return Objects.hash(selected_identity);
        }
    }
}
