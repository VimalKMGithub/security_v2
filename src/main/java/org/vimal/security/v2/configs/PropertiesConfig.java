package org.vimal.security.v2.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class PropertiesConfig {
    private String jwtSecretStatic;
    private String jwtSecretRandom;
    private String refreshTokenSecretStatic;
    private String refreshTokenSecretRandom;
    private String stateTokenSecretStatic;
    private String stateTokenSecretRandom;
    private String emailOtpSecretStatic;
    private String emailOtpSecretRandom;
    private String authenticatorAppMfaSecretStatic;
    private String authenticatorAppMfaSecretRandom;
    private String authenticatorAppSecretRandom;
    private String emailVerificationTokenSecretStatic;
    private String emailVerificationTokenSecretRandom;
    private String emailOtpForPwdResetSecretStatic;
    private String emailOtpForPwdResetSecretRandom;
    private String emailOtpForEmailChangeSecretStatic;
    private String emailOtpForEmailChangeSecretRandom;
    private String emailStoreSecretStatic;
    private String emailStoreSecretRandom;
    private String mailDisplayName;
    private String helpMailAddress;
    private String godUserUsername;
    private String globalAdminUserUsername;
    private String godUserEmail;
    private String globalAdminUserEmail;
    private String godUserPassword;
    private String globalAdminUserPassword;
    private String jwtSigningSecret;
    private String jwtEncryptionSecret;
    private String unleashUrl;
    private String unleashApiToken;
}
