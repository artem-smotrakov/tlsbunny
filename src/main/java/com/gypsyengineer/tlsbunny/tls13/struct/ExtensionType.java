package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface ExtensionType extends Struct {

    int encoding_length = 2;

    ExtensionType application_layer_protocol_negotiation = StructFactory.getDefault().createExtensionType(16);
    ExtensionType certificate_authorities = StructFactory.getDefault().createExtensionType(47);
    ExtensionType client_certificate_type = StructFactory.getDefault().createExtensionType(19);
    ExtensionType cookie = StructFactory.getDefault().createExtensionType(44);
    ExtensionType early_data = StructFactory.getDefault().createExtensionType(42);
    ExtensionType heartbeat = StructFactory.getDefault().createExtensionType(15);
    ExtensionType key_share = StructFactory.getDefault().createExtensionType(51);
    ExtensionType max_fragment_length = StructFactory.getDefault().createExtensionType(1);
    ExtensionType oid_filters = StructFactory.getDefault().createExtensionType(48);
    ExtensionType padding = StructFactory.getDefault().createExtensionType(21);
    ExtensionType post_handshake_auth = StructFactory.getDefault().createExtensionType(49);
    ExtensionType pre_shared_key = StructFactory.getDefault().createExtensionType(41);
    ExtensionType psk_key_exchange_modes = StructFactory.getDefault().createExtensionType(45);
    ExtensionType server_certificate_type = StructFactory.getDefault().createExtensionType(20);
    ExtensionType server_name = StructFactory.getDefault().createExtensionType(0);
    ExtensionType signature_algorithms = StructFactory.getDefault().createExtensionType(13);
    ExtensionType signed_certificate_timestamp = StructFactory.getDefault().createExtensionType(18);
    ExtensionType status_request = StructFactory.getDefault().createExtensionType(5);
    ExtensionType supported_groups = StructFactory.getDefault().createExtensionType(10);
    ExtensionType supported_versions = StructFactory.getDefault().createExtensionType(43);
    ExtensionType use_srtp = StructFactory.getDefault().createExtensionType(14);
    ExtensionType signature_algorithms_cert = StructFactory.getDefault().createExtensionType(50);

    int code();
}
