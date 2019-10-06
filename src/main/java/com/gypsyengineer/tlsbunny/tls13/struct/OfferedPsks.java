package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface OfferedPsks extends Struct {

    int identities_length_bytes = 2;
    int binders_length_bytes = 2;

    Vector<PskIdentity> identities();
    Vector<PskBinderEntry> binders();
}
