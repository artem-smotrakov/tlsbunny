package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface SignatureScheme extends Struct {

    int encoding_length = 2;

    /* ECDSA algorithms */
    SignatureScheme ecdsa_secp256r1_sha256 = StructFactory.getDefault().createSignatureScheme(0x0403);
    SignatureScheme ecdsa_secp384r1_sha384 = StructFactory.getDefault().createSignatureScheme(0x0503);
    SignatureScheme ecdsa_secp521r1_sha512 = StructFactory.getDefault().createSignatureScheme(0x0603);

    /* EdDSA algorithms */
    SignatureScheme ed25519 = StructFactory.getDefault().createSignatureScheme(0x0807);
    SignatureScheme ed448 = StructFactory.getDefault().createSignatureScheme(0x0808);

    /* RSASSA-PKCS1-v1_5 algorithms */
    SignatureScheme rsa_pkcs1_sha256 = StructFactory.getDefault().createSignatureScheme(0x0401);
    SignatureScheme rsa_pkcs1_sha384 = StructFactory.getDefault().createSignatureScheme(0x0501);
    SignatureScheme rsa_pkcs1_sha512 = StructFactory.getDefault().createSignatureScheme(0x0601);

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    SignatureScheme rsa_pss_rsae_sha256 = StructFactory.getDefault().createSignatureScheme(0x0804);
    SignatureScheme rsa_pss_rsae_sha384 = StructFactory.getDefault().createSignatureScheme(0x0805);
    SignatureScheme rsa_pss_rsae_sha512 = StructFactory.getDefault().createSignatureScheme(0x0806);

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    SignatureScheme rsa_pss_pss_sha256 = StructFactory.getDefault().createSignatureScheme(0x0809);
    SignatureScheme rsa_pss_pss_sha384 = StructFactory.getDefault().createSignatureScheme(0x080a);
    SignatureScheme rsa_pss_pss_sha512 = StructFactory.getDefault().createSignatureScheme(0x080b);

    /* Legacy algorithms */
    SignatureScheme rsa_pkcs1_sha1 = StructFactory.getDefault().createSignatureScheme(0x0201);
    SignatureScheme ecdsa_sha1 = StructFactory.getDefault().createSignatureScheme(0x0203);

    int getCode();
}
