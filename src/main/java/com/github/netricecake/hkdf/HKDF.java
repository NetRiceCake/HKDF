package com.github.netricecake.hkdf;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HKDF {

    private String algorithm;

    private HKDF(String algorithm) {
        this.algorithm = algorithm;
    }

    public static HKDF fromHmacSha256() {
        return new HKDF("HmacSHA256");
    }

    public static HKDF fromHmacSha384() {
        return new HKDF("HmacSHA384");
    }

    public byte[] extract(byte[] salt, byte[] keyMaterial) throws NoSuchAlgorithmException, InvalidKeyException {
        return extract(new SecretKeySpec(salt, algorithm), keyMaterial);
    }

    public byte[] extract(SecretKey salt, byte[] keyMaterial) throws NoSuchAlgorithmException, InvalidKeyException {
        if (keyMaterial != null && keyMaterial.length > 0) {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(salt);
            return mac.doFinal(keyMaterial);
        } else {
            return null;
        }
    }

    public byte[] expand(byte[] key, byte[] info, int outLengthBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        return expand(new SecretKeySpec(key, algorithm), info, outLengthBytes);
    }

    public byte[] expand(SecretKey key, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(key);
        if (info == null) info = new byte[0];

        byte[] hashRound = new byte[0];
        ByteBuffer buffer = ByteBuffer.allocate(length);

        for (int i = 0; i < (int) Math.ceil((double) length / (double) mac.getMacLength()); i++) {
            mac.update(hashRound);
            mac.update(info);
            mac.update((byte) (i + 1));
            hashRound = mac.doFinal();
            int size = Math.min(length, hashRound.length);
            buffer.put(hashRound, 0, size);
        }

        return buffer.array();
    }

    public byte[] expandLabel(byte[] key, String label, byte[] context, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        return expandLabel(new SecretKeySpec(key, algorithm), label, context, length);
    }

    public byte[] expandLabel(SecretKey key, String label, byte[] context, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] hexLabel = ("tls13 " + label).getBytes();
        byte[] info = new byte[hexLabel.length + context.length + 4];

        byte[] hexLength = new byte[2];
        hexLength[0] = (byte) (length >> 8);
        hexLength[1] = (byte) (length);

        System.arraycopy(hexLength, 0, info, 0, 2);
        info[2] = (byte) hexLabel.length;
        System.arraycopy(hexLabel, 0, info, 3, hexLabel.length);
        info[hexLabel.length + 3] = (byte) context.length;
        System.arraycopy(context, 0, info, hexLabel.length + 4, context.length);

        return expand(key, info, length);
    }

}
