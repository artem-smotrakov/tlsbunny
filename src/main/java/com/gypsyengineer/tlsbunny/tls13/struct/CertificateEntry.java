package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface CertificateEntry extends Struct {

    int extensions_length_bytes = 2;

    Extension extension(ExtensionType type);
    Vector<Extension> extensions();
    
    interface X509 extends CertificateEntry {
    
        int length_bytes = 3;

        Vector<Byte> certData();
    }

    interface RawPublicKey extends CertificateEntry {
    
        int length_bytes = 3;
        
        Vector<Byte> asn1SubjectPublicKeyInfo();
    }
}
