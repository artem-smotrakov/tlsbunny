package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface KeyShare extends Struct {
    
    interface ClientHello extends KeyShare {

        int length_bytes = 2;

        Vector<KeyShareEntry> getClientShares();
    }

    interface ServerHello extends KeyShare {
        KeyShareEntry getServerShare();
    }
    
    interface HelloRetryRequest extends KeyShare {
        NamedGroup getSelectedGroup();
    }
}
