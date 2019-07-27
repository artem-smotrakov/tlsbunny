package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TranscriptHash {

    private final MessageDigest md;

    private TranscriptHash(MessageDigest md) {
        this.md = md;
    }

    public void update(Handshake... messages) throws IOException {
        if (messages != null && messages.length != 0) {
            for (Handshake message : messages) {
                update(message.encoding());
            }
        } else {
            update(new byte[0]);
        }
    }
    
    public byte[] compute(Handshake... messages) throws IOException {
        reset();
        update(messages);
        return get();
    }

    public byte[] get() {
        return md.digest();
    }

    public void update(byte[] bytes) {
        md.update(bytes);
    }
    
    public void reset() {
        md.reset();
    }

    public static TranscriptHash create(String algorithm) 
            throws NoSuchAlgorithmException {
        
        return new TranscriptHash(MessageDigest.getInstance(algorithm));
    }

    public static byte[] compute(String algorithm, Handshake... messages)
            throws NoSuchAlgorithmException, IOException {

        TranscriptHash hash = create(algorithm);
       
        if (messages != null) {
            for (Handshake message : messages) {
                hash.update(message);
            } 
        } else {
            hash.update(new byte[0]);
        }
        
        return hash.get();
    }

}
