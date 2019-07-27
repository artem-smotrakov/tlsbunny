package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.utils.Utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcmEncryptor extends AesGcm {

    private List<byte[]> cipherTexts = new ArrayList<>();

    AesGcmEncryptor(Cipher cipher, Key key, byte[] iv) {
        super(cipher, key, iv);
    }

    @Override
    public void start() throws AEADException {
        cipherTexts.clear();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key,
                    new GCMParameterSpec(tag_length_in_bits, nextNonce()));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new AEADException(e);
        }
    }

    @Override
    public byte[] update(byte[] data) {
        byte[] ciphertext = cipher.update(data);
        cipherTexts.add(ciphertext);

        return ciphertext.clone();
    }

    @Override
    public void updateAAD(byte[] data) {
        cipher.updateAAD(data);
    }

    @Override
    public byte[] finish() throws AEADException {
        try {
            cipherTexts.add(cipher.doFinal());
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new AEADException(e);
        }

        return Utils.concatenate(cipherTexts);
    }

    public static AesGcmEncryptor create(byte[] key, byte[] iv)
            throws AEADException {

        try {
            return new AesGcmEncryptor(
                    Cipher.getInstance(transform),
                    new SecretKeySpec(key, algorithm),
                    iv);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new AEADException(e);
        }
    }

}
