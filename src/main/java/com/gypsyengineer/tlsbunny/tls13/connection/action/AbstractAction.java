package com.gypsyengineer.tlsbunny.tls13.connection.action;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.output.Output;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.gypsyengineer.tlsbunny.utils.Utils.SEED;

public abstract class AbstractAction<T extends AbstractAction> implements Action {

    protected ByteBuffer in;
    protected ByteBuffer out;
    protected ByteBuffer applicationDataIn;
    protected ByteBuffer applicationDataOut;
    protected Output output;
    protected Context context;

    @Override
    public String name() {
        return "unknown action";
    }

    @Override
    public T set(Output output) {
        this.output = output;
        return (T) this;
    }

    @Override
    public T set(Context context) {
        this.context = context;
        return (T) this;
    }

    @Override
    public T in(ByteBuffer buffer) {
        this.in = buffer;
        return (T) this;
    }

    public T in(byte[] data) {
        return in(ByteBuffer.wrap(data));
    }

    @Override
    public ByteBuffer out() {
        return out;
    }

    @Override
    public T applicationData(ByteBuffer buffer) {
        applicationDataIn = buffer;
        return (T) this;
    }

    @Override
    public ByteBuffer applicationData() {
        return applicationDataOut;
    }

    // helper methods

    protected byte[] processEncrypted(AEAD decryptor, ContentType expectedType)
            throws ActionFailed, AEADException, IOException {

        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);
        if (tlsPlaintext.containsAlert()) {
            Alert alert = context.factory().parser().parseAlert(tlsPlaintext.getFragment());
            context.setAlert(alert);
            throw new ActionFailed(String.format("received an alert: %s", alert));
        }

        if (!tlsPlaintext.containsApplicationData()) {
            throw new ActionFailed("expected a TLSCiphertext");
        }

        TLSInnerPlaintext tlsInnerPlaintext = decrypt(decryptor, tlsPlaintext);

        if (!expectedType.isAlert() && tlsInnerPlaintext.containsAlert()) {
            Alert alert = context.factory().parser().parseAlert(tlsInnerPlaintext.getContent());
            context.setAlert(alert);
            throw new ActionFailed(String.format("received an alert: %s", alert));
        }

        if (!expectedType.equals(tlsInnerPlaintext.getType())) {
            throw new ActionFailed(
                    String.format("expected %, but received %s",
                            expectedType, tlsInnerPlaintext.getType()));
        }

        return tlsInnerPlaintext.getContent();
    }

    protected Handshake processEncryptedHandshake()
            throws AEADException, ActionFailed, IOException {

        return context.factory().parser().parseHandshake(
                processEncrypted(context.handshakeDecryptor(), ContentType.handshake));
    }

    protected Handshake toHandshake(HandshakeMessage message) throws IOException {
        return context.factory().createHandshake(message.type(), message.encoding());
    }

    protected Extension wrap(SupportedVersions supportedVersions) throws IOException {
        return context.factory().createExtension(
                ExtensionType.supported_versions, supportedVersions.encoding());
    }

    protected Extension wrap(SignatureSchemeList signatureSchemeList) throws IOException {
        return context.factory().createExtension(
                ExtensionType.signature_algorithms, signatureSchemeList.encoding());
    }

    protected Extension wrap(NamedGroupList namedGroupList) throws IOException {
        return context.factory().createExtension(
                ExtensionType.supported_groups, namedGroupList.encoding());
    }

    protected Extension wrap(KeyShare keyShare) throws IOException {
        return context.factory().createExtension(
                ExtensionType.key_share, keyShare.encoding());
    }

    protected Extension wrap(Cookie cookie) throws IOException {
        return context.factory().createExtension(ExtensionType.cookie, cookie.encoding());
    }

    protected Extension wrap(MaxFragmentLength maxFragmentLength) throws IOException {
        return context.factory().createExtension(
                ExtensionType.max_fragment_length, maxFragmentLength.encoding());
    }

    protected TLSInnerPlaintext decrypt(AEAD decryptor, TLSPlaintext tlsPlaintext)
            throws AEADException {

        return context.factory().parser().parseTLSInnerPlaintext(
                decryptor.decrypt(tlsPlaintext));
    }

    public static Random createRandom() {
        java.util.Random generator = new java.util.Random(SEED);
        byte[] random_bytes = new byte[Random.length];
        generator.nextBytes(random_bytes);
        Random random = Random.create();
        random.setBytes(random_bytes);

        return random;
    }
}
