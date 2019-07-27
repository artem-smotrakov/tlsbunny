package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;

public interface CipherSuite extends Struct {

    int encoding_length = 2;
    String unknown = "unknown";
        
    CipherSuite TLS_AES_128_CCM_8_SHA256 = StructFactory.getDefault().createCipherSuite(0x13, 0x05);
    CipherSuite TLS_AES_128_CCM_SHA256 = StructFactory.getDefault().createCipherSuite(0x13, 0x04);
    CipherSuite TLS_AES_128_GCM_SHA256 = StructFactory.getDefault().createCipherSuite(0x13, 0x01);
    CipherSuite TLS_AES_256_GCM_SHA384 = StructFactory.getDefault().createCipherSuite(0x13, 0x02);
    CipherSuite TLS_CHACHA20_POLY1305_SHA256 = StructFactory.getDefault().createCipherSuite(0x13, 0x03);

    AEAD.Method cipher();
    int getFirst();
    int getSecond();
    String hash();
    int hashLength();
    int ivLength();
    int keyLength();
}
