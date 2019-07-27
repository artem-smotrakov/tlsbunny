package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.utils.Converter;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

class FFDHEParameters {
    
    private static final BigInteger ffdhe2048_p = Converter.hex2int(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
            "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
            "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
            "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
            "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
            "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
            "886B423861285C97FFFFFFFFFFFFFFFF");

    private static final BigInteger ffdhe2048_g = BigInteger.TWO;

    private static final Map<NamedGroup, FFDHEParameters> parameters = new HashMap<>();
    static {
        parameters.put(NamedGroup.ffdhe2048,
                new FFDHEParameters(ffdhe2048_p, ffdhe2048_g));
    }

    public final DHParameterSpec spec;

    public FFDHEParameters(BigInteger p, BigInteger g) {
        this.spec = new DHParameterSpec(p, g);
    }

    public static FFDHEParameters create(NamedGroup group) {
        return parameters.get(group);
    }
    
}
