package org.vimal.security.v2.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class AESRandomUtility {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final SecureRandom secureRandom = new SecureRandom();
    private final ObjectMapper objectMapper;
    private final SecretKey secretKey;

    public AESRandomUtility(String aesSecret,
                            ObjectMapper objectMapper) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(aesSecret.getBytes()), "AES");
        this.objectMapper = objectMapper;
    }

    public String encrypt(Object data) throws JsonProcessingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptString(objectMapper.writeValueAsString(data));
    }

    public String encryptString(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        var cipher = Cipher.getInstance(TRANSFORMATION);
        var gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        var encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public <T> T decrypt(String encryptedData,
                         Class<T> targetClass) throws JsonProcessingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return objectMapper.readValue(decryptString(encryptedData), targetClass);
    }

    public String decryptString(String encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var parts = encryptedData.split(":");
        var iv = Base64.getDecoder().decode(parts[0]);
        var encryptedBytes = Base64.getDecoder().decode(parts[1]);
        var cipher = Cipher.getInstance(TRANSFORMATION);
        var gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        return new String(cipher.doFinal(encryptedBytes));
    }
}
