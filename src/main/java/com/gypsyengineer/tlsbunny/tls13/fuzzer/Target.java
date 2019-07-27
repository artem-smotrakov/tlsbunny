package com.gypsyengineer.tlsbunny.tls13.fuzzer;

public enum Target {
    tls_plaintext,
    handshake,
    ccs,

    // handshake messages
    client_hello,
    server_hello,
    certificate,
    certificate_verify,
    certificate_request,
    encrypted_extensions,
    finished,

    // smaller targets
    legacy_session_id
}