package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;

public interface AEAD {

    enum Method {
        aes_128_gcm,
        aes_256_gcm,
        chacha20_poly1305,
        aes_128_ccm,
        aes_128_ccm_8,
        unknown
    }

    void start() throws AEADException;
    byte[] update(byte[] data) throws AEADException;
    void updateAAD(byte[] data) throws AEADException;
    byte[] finish() throws AEADException;

    byte[] decrypt(TLSPlaintext tlsCiphertext) throws AEADException;
    
    static AEAD createEncryptor(Method cipher, byte[] key, byte[] iv)
            throws AEADException {
        
        switch (cipher) {
            case aes_128_gcm:
            case aes_256_gcm:
                return AesGcmEncryptor.create(key, iv);
            case chacha20_poly1305:
            case aes_128_ccm:
            case aes_128_ccm_8:
                throw new IllegalArgumentException("Unsupported cipher: " + cipher);
            default:
                throw new IllegalArgumentException("Unknown cipher: " + cipher);
        }
    }
    
    static AEAD createDecryptor(Method cipher, byte[] key, byte[] iv)
            throws AEADException {
        
        switch (cipher) {
            case aes_128_gcm:
            case aes_256_gcm:
                return AesGcmDecryptor.create(key, iv);
            case chacha20_poly1305:
            case aes_128_ccm:
            case aes_128_ccm_8:
                throw new IllegalArgumentException("Unsupported cipher: " + cipher);
            default:
                throw new IllegalArgumentException("Unknown cipher: " + cipher);
        }
    }

    static byte[] getAdditionalData(int length) throws IOException {
        return getAdditionalData(new UInt16(length));
    }

    static byte[] getAdditionalData(UInt16 length) throws IOException {
        return Utils.concatenate(
                ContentType.application_data.encoding(),
                ProtocolVersion.TLSv12.encoding(),
                length.encoding());
    }
}
