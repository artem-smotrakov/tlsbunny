package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface NamedGroup extends Struct {

    int encoding_length = 2;
    
    FFDHE ffdhe2048 = StructFactory.getDefault().createFFDHENamedGroup(0x0100);
    FFDHE ffdhe3072 = StructFactory.getDefault().createFFDHENamedGroup(0x0101);
    FFDHE ffdhe4096 = StructFactory.getDefault().createFFDHENamedGroup(0x0102);
    FFDHE ffdhe6144 = StructFactory.getDefault().createFFDHENamedGroup(0x0103);
    FFDHE ffdhe8192 = StructFactory.getDefault().createFFDHENamedGroup(0x0104);
    Secp secp256r1 = StructFactory.getDefault().createSecpNamedGroup(0x0017, "secp256r1");
    Secp secp384r1 = StructFactory.getDefault().createSecpNamedGroup(0x0018, "secp384r1");
    Secp secp521r1 = StructFactory.getDefault().createSecpNamedGroup(0x0019, "secp521r1");
    X x25519 = StructFactory.getDefault().createXNamedGroup(0x001D);
    X x448 = StructFactory.getDefault().createXNamedGroup(0x001E);

    public static interface Secp extends NamedGroup {

        String getCurve();
    }
    
    public static interface X extends NamedGroup {
        
    }
    
    public static interface FFDHE extends NamedGroup {
        
    }
    
}
