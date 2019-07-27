package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.HKDF;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.util.ArrayList;
import java.util.List;

public class Context {

    public enum Element {
        first_client_hello,
        hello_retry_request,
        second_client_hello,
        server_hello,
        encrypted_extensions,
        server_certificate_request,
        server_certificate,
        server_certificate_verify,
        server_finished,
        end_of_early_data,
        client_certificate,
        client_certificate_verify,
        client_finished
    }

    private Handshake firstClientHello;
    private Handshake helloRetryRequest;
    private Handshake secondClientHello;
    private Handshake serverHello;
    private Handshake encryptedExtensions;
    private Handshake serverCertificateRequest;
    private Handshake serverCertificate;
    private Handshake serverCertificateVerify;
    private Handshake serverFinished;
    private Handshake endOfEarlyData;
    private Handshake clientCertificate;
    private Handshake clientCertificateVerify;
    private Handshake clientFinished;

    private boolean clientFinishedVerified = false;
    private boolean serverFinishedVerified = false;

    private StructFactory factory;
    private SignatureScheme scheme;

    private CipherSuite suite;
    private Negotiator negotiator;
    private HKDF hkdf;

    private byte[] dh_shared_secret;
    private byte[] early_secret;
    private byte[] binder_key;
    private byte[] client_early_traffic_secret;
    private byte[] early_exporter_master_secret;
    private byte[] handshake_secret_salt;
    private byte[] handshake_secret;
    private byte[] client_handshake_traffic_secret;
    private byte[] server_handshake_traffic_secret;
    private byte[] master_secret;
    private byte[] client_application_traffic_secret_0;
    private byte[] server_application_traffic_secret_0;
    private byte[] exporter_master_secret;
    private byte[] resumption_master_secret;
    private byte[] client_handshake_write_key;
    private byte[] client_handshake_write_iv;
    private byte[] server_handshake_write_key;
    private byte[] server_handshake_write_iv;
    private byte[] finished_key;
    private byte[] client_application_write_key;
    private byte[] client_application_write_iv;
    private byte[] server_application_write_key;
    private byte[] server_application_write_iv;

    private Vector<Byte> certificate_request_context;

    private Alert alert;

    private  AEAD handshakeEncryptor;
    private AEAD handshakeDecryptor;
    private AEAD applicationDataEncryptor;
    private AEAD applicationDataDecryptor;

    private  List<byte[]> applicationData = new ArrayList<>();

    public Vector<Byte> certificateRequestContext() {
        return certificate_request_context;
    }

    public Context certificateRequestContext(Vector<Byte> certificate_request_context) {
        this.certificate_request_context = certificate_request_context;
        return this;
    }

    public AEAD handshakeEncryptor() {
        return handshakeEncryptor;
    }

    public Context handshakeEncryptor(AEAD handshakeEncryptor) {
        this.handshakeEncryptor = handshakeEncryptor;
        return this;
    }

    public AEAD handshakeDecryptor() {
        return handshakeDecryptor;
    }

    public Context handshakeDecryptor(AEAD handshakeDecryptor) {
        this.handshakeDecryptor = handshakeDecryptor;
        return this;
    }

    public AEAD applicationDataEncryptor() {
        return applicationDataEncryptor;
    }

    public Context applicationDataEncryptor(AEAD applicationDataEncryptor) {
        this.applicationDataEncryptor = applicationDataEncryptor;
        return this;
    }

    public AEAD applicationDataDecryptor() {
        return applicationDataDecryptor;
    }

    public Context applicationDataDecryptor(AEAD applicationDataDecryptor) {
        this.applicationDataDecryptor = applicationDataDecryptor;
        return this;
    }

    public List<byte[]> applicationData() {
        return applicationData;
    }

    public Context applicationData(byte[] bytes) {
        this.applicationData.add(bytes);
        return this;
    }

    public Context set(HKDF hkdf) {
        this.hkdf = hkdf;
        return this;
    }

    public HKDF hkdf() {
        return hkdf;
    }

    public Context set(Negotiator negotiator) {
        this.negotiator = negotiator;
        return this;
    }

    public Negotiator negotiator() {
        return negotiator;
    }

    public Context set(CipherSuite suite) {
        this.suite = suite;
        return this;
    }

    public CipherSuite suite() {
        return suite;
    }

    public Context set(StructFactory factory) {
        this.factory = factory;
        return this;
    }

    public StructFactory factory() {
        return factory;
    }

    public Context set(SignatureScheme scheme) {
        this.scheme = scheme;
        return this;
    }

    public SignatureScheme scheme() {
        return scheme;
    }

    public byte[] dh_shared_secret() {
        return dh_shared_secret;
    }

    public void dh_shared_secret(byte[] dh_shared_secret) {
        this.dh_shared_secret = dh_shared_secret;
    }

    public byte[] early_secret() {
        return early_secret;
    }

    public void early_secret(byte[] early_secret) {
        this.early_secret = early_secret;
    }

    public byte[] binder_key() {
        return binder_key;
    }

    public void binder_key(byte[] binder_key) {
        this.binder_key = binder_key;
    }

    public byte[] client_early_traffic_secret() {
        return client_early_traffic_secret;
    }

    public void client_early_traffic_secret(byte[] client_early_traffic_secret) {
        this.client_early_traffic_secret = client_early_traffic_secret;
    }

    public byte[] early_exporter_master_secret() {
        return early_exporter_master_secret;
    }

    public void early_exporter_master_secret(byte[] early_exporter_master_secret) {
        this.early_exporter_master_secret = early_exporter_master_secret;
    }

    public byte[] handshake_secret_salt() {
        return handshake_secret_salt;
    }

    public void handshake_secret_salt(byte[] handshake_secret_salt) {
        this.handshake_secret_salt = handshake_secret_salt;
    }

    public byte[] handshake_secret() {
        return handshake_secret;
    }

    public void handshake_secret(byte[] handshake_secret) {
        this.handshake_secret = handshake_secret;
    }

    public byte[] client_handshake_traffic_secret() {
        return client_handshake_traffic_secret;
    }

    public void client_handshake_traffic_secret(byte[] client_handshake_traffic_secret) {
        this.client_handshake_traffic_secret = client_handshake_traffic_secret;
    }

    public byte[] server_handshake_traffic_secret() {
        return server_handshake_traffic_secret;
    }

    public void server_handshake_traffic_secret(byte[] server_handshake_traffic_secret) {
        this.server_handshake_traffic_secret = server_handshake_traffic_secret;
    }

    public byte[] master_secret() {
        return master_secret;
    }

    public void master_secret(byte[] master_secret) {
        this.master_secret = master_secret;
    }

    public byte[] client_application_traffic_secret_0() {
        return client_application_traffic_secret_0;
    }

    public void client_application_traffic_secret_0(byte[] client_application_traffic_secret_0) {
        this.client_application_traffic_secret_0 = client_application_traffic_secret_0;
    }

    public byte[] server_application_traffic_secret_0() {
        return server_application_traffic_secret_0;
    }

    public void server_application_traffic_secret_0(byte[] server_application_traffic_secret_0) {
        this.server_application_traffic_secret_0 = server_application_traffic_secret_0;
    }

    public byte[] exporter_master_secret() {
        return exporter_master_secret;
    }

    public void exporter_master_secret(byte[] exporter_master_secret) {
        this.exporter_master_secret = exporter_master_secret;
    }

    public byte[] resumption_master_secret() {
        return resumption_master_secret;
    }

    public void resumption_master_secret(byte[] resumption_master_secret) {
        this.resumption_master_secret = resumption_master_secret;
    }

    public byte[] client_handshake_write_key() {
        return client_handshake_write_key;
    }

    public void client_handshake_write_key(byte[] client_handshake_write_key) {
        this.client_handshake_write_key = client_handshake_write_key;
    }

    public byte[] client_handshake_write_iv() {
        return client_handshake_write_iv;
    }

    public void client_handshake_write_iv(byte[] client_handshake_write_iv) {
        this.client_handshake_write_iv = client_handshake_write_iv;
    }

    public byte[] server_handshake_write_key() {
        return server_handshake_write_key;
    }

    public void server_handshake_write_key(byte[] server_handshake_write_key) {
        this.server_handshake_write_key = server_handshake_write_key;
    }

    public byte[] server_handshake_write_iv() {
        return server_handshake_write_iv;
    }

    public void server_handshake_write_iv(byte[] server_handshake_write_iv) {
        this.server_handshake_write_iv = server_handshake_write_iv;
    }

    public byte[] finished_key() {
        return finished_key;
    }

    public void finished_key(byte[] finished_key) {
        this.finished_key = finished_key;
    }

    public byte[] client_application_write_key() {
        return client_application_write_key;
    }

    public void client_application_write_key(byte[] client_application_write_key) {
        this.client_application_write_key = client_application_write_key;
    }

    public byte[] client_application_write_iv() {
        return client_application_write_iv;
    }

    public void client_application_write_iv(byte[] client_application_write_iv) {
        this.client_application_write_iv = client_application_write_iv;
    }

    public byte[] server_application_write_key() {
        return server_application_write_key;
    }

    public void server_application_write_key(byte[] server_application_write_key) {
        this.server_application_write_key = server_application_write_key;
    }

    public byte[] server_application_write_iv() {
        return server_application_write_iv;
    }

    public void server_application_write_iv(byte[] server_application_write_iv) {
        this.server_application_write_iv = server_application_write_iv;
    }

    public boolean hasFirstClientHello() {
        return firstClientHello != null;
    }

    public boolean hasSecondClientHello() {
        return secondClientHello != null;
    }

    public Handshake getFirstClientHello() {
        return firstClientHello;
    }

    public void setFirstClientHello(Handshake firstClientHello) {
        this.firstClientHello = firstClientHello;
    }

    public void setHelloRetryRequest(Handshake helloRetryRequest) {
        this.helloRetryRequest = helloRetryRequest;
    }

    public void setSecondClientHello(Handshake secondClientHello) {
        this.secondClientHello = secondClientHello;
    }

    public Handshake getServerHello() {
        return serverHello;
    }

    public void setServerHello(Handshake serverHello) {
        this.serverHello = serverHello;
    }

    public boolean hasServerHello() {
        return serverHello != null;
    }

    public void setEncryptedExtensions(Handshake encryptedExtensions) {
        this.encryptedExtensions = encryptedExtensions;
    }

    public void setServerCertificateRequest(Handshake serverCertificateRequest) {
        this.serverCertificateRequest = serverCertificateRequest;
    }

    public Handshake getServerCertificate() {
        return serverCertificate;
    }

    public void setServerCertificate(Handshake serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public void setServerCertificateVerify(Handshake serverCertificateVerify) {
        this.serverCertificateVerify = serverCertificateVerify;
    }

    public void setServerFinished(Handshake serverFinished) {
        this.serverFinished = serverFinished;
    }

    public boolean receivedServerFinished() {
        return serverFinished != null;
    }

    public boolean receivedClientFinished() {
        return clientFinished != null;
    }

    public void verifyClientFinished() {
        clientFinishedVerified = true;
    }

    public void verifyServerFinished() {
        serverFinishedVerified = true;
    }

    public void setEndOfEarlyData(Handshake endOfEarlyData) {
        this.endOfEarlyData = endOfEarlyData;
    }

    public void setClientCertificate(Handshake clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    public void setClientCertificateVerify(Handshake clientCertificateVerify) {
        this.clientCertificateVerify = clientCertificateVerify;
    }

    public void setClientFinished(Handshake clientFinished) {
        this.clientFinished = clientFinished;
    }

    public void set(Element element, Handshake message) {
        switch (element) {
            case first_client_hello:
                setFirstClientHello(message);
                break;
            case hello_retry_request:
                setHelloRetryRequest(message);
                break;
            case second_client_hello:
                setSecondClientHello(message);
                break;
            case server_hello:
                setServerHello(message);
                break;
            case encrypted_extensions:
                setEncryptedExtensions(message);
                break;
            case server_certificate_request:
                setServerCertificateRequest(message);
                break;
            case server_certificate:
                setServerCertificate(message);
                break;
            case server_certificate_verify:
                setServerCertificateVerify(message);
                break;
            case server_finished:
                setServerFinished(message);
                break;
            case end_of_early_data:
                setEndOfEarlyData(message);
                break;
            case client_certificate:
                setClientCertificate(message);
                break;
            case client_certificate_verify:
                setClientCertificateVerify(message);
                break;
            case client_finished:
                setClientFinished(message);
                break;
            default:
                throw new IllegalArgumentException();
        }
    }

    public Handshake[] messagesForApplicationKeys() {
        return noNulls(new Handshake[] {
                firstClientHello,
                helloRetryRequest,
                secondClientHello,
                serverHello,
                encryptedExtensions,
                serverCertificateRequest,
                serverCertificate,
                serverCertificateVerify,
                serverFinishedVerified ? serverFinished : null,
                endOfEarlyData,
                clientFinishedVerified ? clientFinished : null,
        });
    }

    public Handshake[] allMessages() {
        return noNulls(new Handshake[] {
                firstClientHello,
                helloRetryRequest,
                secondClientHello,
                serverHello,
                encryptedExtensions,
                serverCertificateRequest,
                serverCertificate,
                serverCertificateVerify,
                serverFinishedVerified ? serverFinished : null,
                endOfEarlyData,
                clientCertificate,
                clientCertificateVerify,
                clientFinishedVerified ? clientFinished : null,
        });
    }

    synchronized public boolean hasAlert() {
        return alert != null;
    }

    synchronized public void setAlert(Alert alert) {
        this.alert = alert;
    }

    synchronized public Alert getAlert() {
        return alert;
    }

    public void addApplicationData(byte[] data) {
        applicationData.add(data);
    }

    public boolean receivedApplicationData() {
        return !applicationData.isEmpty();
    }

    private static Handshake[] noNulls(Handshake[] messages) {
        List<Handshake> list = new ArrayList<>();
        for (Handshake message : messages) {
            if (message != null) {
                list.add(message);
            }
        }

        return list.toArray(new Handshake[0]);
    }

}
