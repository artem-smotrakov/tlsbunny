package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface SupportedVersions extends Struct {

    public static interface ClientHello extends SupportedVersions {

        int versions_length_bytes = 1;

        Vector<ProtocolVersion> getVersions();
    }
    
    public static interface ServerHello extends SupportedVersions {

        ProtocolVersion getSelectedVersion();
    }
    
}
