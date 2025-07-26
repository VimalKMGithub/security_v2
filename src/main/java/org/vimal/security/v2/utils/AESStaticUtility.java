package org.vimal.security.v2.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESStaticUtility {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final byte[] FIXED_IV = new byte[16];
    private final ObjectMapper objectMapper;
    private final SecretKey secretKey;

    public AESStaticUtility(String aesSecret,
                            ObjectMapper objectMapper) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(aesSecret.getBytes()), "AES");
        this.objectMapper = objectMapper;
    }

    public String encrypt(Object data) throws JsonProcessingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptString(objectMapper.writeValueAsString(data));
    }

    public String encryptString(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance(TRANSFORMATION);
        var ivSpec = new IvParameterSpec(FIXED_IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        var encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public <T> T decrypt(String encryptedData,
                         Class<T> targetClass) throws JsonProcessingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return objectMapper.readValue(decryptString(encryptedData), targetClass);
    }

    public String decryptString(String encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance(TRANSFORMATION);
        var ivSpec = new IvParameterSpec(FIXED_IV);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        var decodedBytes = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedBytes));
    }
}
