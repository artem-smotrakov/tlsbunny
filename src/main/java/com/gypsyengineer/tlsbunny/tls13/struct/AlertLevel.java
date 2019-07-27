package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface AlertLevel extends Struct {

    int encoding_length = 1;
    int max = 255;
    int min = 0;
    
    AlertLevel fatal = StructFactory.getDefault().createAlertLevel(2);
    AlertLevel warning = StructFactory.getDefault().createAlertLevel(1);

    byte getCode();
}
