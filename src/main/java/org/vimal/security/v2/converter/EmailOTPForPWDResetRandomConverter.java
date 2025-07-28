package org.vimal.security.v2.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.vimal.security.v2.configs.PropertiesConfig;
import org.vimal.security.v2.utils.AESRandomUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EmailOTPForPWDResetRandomConverter {
    private final AESRandomUtility aesRandomUtility;

    public EmailOTPForPWDResetRandomConverter(PropertiesConfig propertiesConfig,
                                              ObjectMapper objectMapper) throws NoSuchAlgorithmException {
        this.aesRandomUtility = new AESRandomUtility(propertiesConfig.getEmailOtpForPwdResetSecretRandom(), objectMapper);
    }

    public String encrypt(Object data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return aesRandomUtility.encrypt(data);
    }

    public <T> T decrypt(String encryptedData,
                         Class<T> targetClass) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return aesRandomUtility.decrypt(encryptedData, targetClass);
    }
}
