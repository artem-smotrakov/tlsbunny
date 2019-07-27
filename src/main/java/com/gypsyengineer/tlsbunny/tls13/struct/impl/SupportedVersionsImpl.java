package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.SupportedVersions;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class SupportedVersionsImpl implements SupportedVersions {

    public static class ClientHelloImpl implements ClientHello {
        
        private Vector<ProtocolVersion> versions;
        
        ClientHelloImpl(Vector<ProtocolVersion> versions) {
            this.versions = versions;
        }
        
        @Override
        public Vector<ProtocolVersion> getVersions() {
            return versions;
        }
        
        @Override
        public int encodingLength() {
            return versions.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return versions.encoding();
        }

        @Override
        public ClientHelloImpl copy() {
            return new ClientHelloImpl((Vector<ProtocolVersion>) versions.copy());
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
            return Objects.equals(versions, that.versions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(versions);
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
                    return versions;
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
                    versions = cast(element, Vector.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }
    }
    
    public static class ServerHelloImpl implements SupportedVersions.ServerHello {
        
        private ProtocolVersion selected_version;

        ServerHelloImpl(ProtocolVersion selected_version) {
            this.selected_version = selected_version;
        }

        @Override
        public ProtocolVersion getSelectedVersion() {
            return selected_version;
        }

        @Override
        public int encodingLength() {
            return selected_version.encodingLength();
        }

        @Override
        public byte[] encoding() throws IOException {
            return selected_version.encoding();
        }

        @Override
        public ServerHelloImpl copy() {
            return new ServerHelloImpl((ProtocolVersion) selected_version.copy());
        }

        @Override
        public String toString() {
            return String.format("SupportedVersion { ServerHello, selected_version: %s }", selected_version);
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
            return Objects.equals(selected_version, that.selected_version);
        }

        @Override
        public int hashCode() {
            return Objects.hash(selected_version);
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
                    return selected_version;
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
                    selected_version = cast(element, ProtocolVersion.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }
    }
}
