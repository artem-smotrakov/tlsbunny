package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface AlertDescription extends Struct {

    int encoding_length = 1;
    int max = 255;
    int min = 0;

    AlertDescription access_denied = StructFactory.getDefault().createAlertDescription(49);
    AlertDescription bad_certificate = StructFactory.getDefault().createAlertDescription(42);
    AlertDescription bad_certificate_hash_value = StructFactory.getDefault().createAlertDescription(114);
    AlertDescription bad_certificate_status_response = StructFactory.getDefault().createAlertDescription(113);
    AlertDescription bad_record_mac = StructFactory.getDefault().createAlertDescription(20);
    AlertDescription certificate_expired = StructFactory.getDefault().createAlertDescription(45);
    AlertDescription certificate_required = StructFactory.getDefault().createAlertDescription(116);
    AlertDescription certificate_revoked = StructFactory.getDefault().createAlertDescription(44);
    AlertDescription certificate_unknown = StructFactory.getDefault().createAlertDescription(46);
    AlertDescription certificate_unobtainable = StructFactory.getDefault().createAlertDescription(111);
    AlertDescription close_notify = StructFactory.getDefault().createAlertDescription(0);
    AlertDescription decode_error = StructFactory.getDefault().createAlertDescription(50);
    AlertDescription decrypt_error = StructFactory.getDefault().createAlertDescription(51);
    AlertDescription handshake_failure = StructFactory.getDefault().createAlertDescription(40);
    AlertDescription illegal_parameter = StructFactory.getDefault().createAlertDescription(47);
    AlertDescription inappropriate_fallback = StructFactory.getDefault().createAlertDescription(86);
    AlertDescription insufficient_security = StructFactory.getDefault().createAlertDescription(71);
    AlertDescription internal_error = StructFactory.getDefault().createAlertDescription(80);
    AlertDescription missing_extension = StructFactory.getDefault().createAlertDescription(109);
    AlertDescription no_application_protocol = StructFactory.getDefault().createAlertDescription(120);
    AlertDescription protocol_version = StructFactory.getDefault().createAlertDescription(70);
    AlertDescription record_overflow = StructFactory.getDefault().createAlertDescription(22);
    AlertDescription unexpected_message = StructFactory.getDefault().createAlertDescription(10);
    AlertDescription unknown_ca = StructFactory.getDefault().createAlertDescription(48);
    AlertDescription unknown_psk_identity = StructFactory.getDefault().createAlertDescription(115);
    AlertDescription unrecognized_name = StructFactory.getDefault().createAlertDescription(112);
    AlertDescription unsupported_certificate = StructFactory.getDefault().createAlertDescription(43);
    AlertDescription unsupported_extension = StructFactory.getDefault().createAlertDescription(110);
    AlertDescription user_cancelled = StructFactory.getDefault().createAlertDescription(90);

    byte getCode();
}
