package org.vimal.security.v2.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.vimal.security.v2.configs.PropertiesConfig;
import org.vimal.security.v2.converter.JWTRandomConverter;
import org.vimal.security.v2.converter.JWTStaticConverter;
import org.vimal.security.v2.converter.RefreshTokenRandomConverter;
import org.vimal.security.v2.converter.RefreshTokenStaticConverter;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.PermissionModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.services.RedisService;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JWTUtility {
    private static final long ACCESS_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(30);
    private static final long REFRESH_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(60 * 24 * 7);
    private static final Duration ACCESS_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);
    private static final Duration REFRESH_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);
    private static final String JWT_ID_PREFIX = "SECURITY_V2_JWT_ID:";
    private static final String REFRESH_TOKEN_PREFIX = "SECURITY_V2_REFRESH_TOKEN:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "SECURITY_V2_REFRESH_TOKEN_MAPPING:";
    private final SecretKey signingKey;
    private final SecretKey encryptionKey;
    private final UserRepo userRepo;
    private final RedisService redisService;
    private final JWTStaticConverter jwtStaticConverter;
    private final JWTRandomConverter jwtRandomConverter;
    private final RefreshTokenStaticConverter refreshTokenStaticConverter;
    private final RefreshTokenRandomConverter refreshTokenRandomConverter;

    public JWTUtility(PropertiesConfig propertiesConfig,
                      UserRepo userRepo,
                      RedisService redisService,
                      JWTStaticConverter jwtStaticConverter,
                      JWTRandomConverter jwtRandomConverter,
                      RefreshTokenStaticConverter refreshTokenStaticConverter,
                      RefreshTokenRandomConverter refreshTokenRandomConverter) throws NoSuchAlgorithmException {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesConfig.getJwtSigningSecret()));
        this.encryptionKey = new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(propertiesConfig.getJwtEncryptionSecret().getBytes()), "AES");
        this.userRepo = userRepo;
        this.redisService = redisService;
        this.jwtStaticConverter = jwtStaticConverter;
        this.jwtRandomConverter = jwtRandomConverter;
        this.refreshTokenStaticConverter = refreshTokenStaticConverter;
        this.refreshTokenRandomConverter = refreshTokenRandomConverter;
    }

    private UUID generateJWTId(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var jwtId = UUID.randomUUID();
        redisService.save(jwtStaticConverter.encrypt(JWT_ID_PREFIX + user.getId()), jwtRandomConverter.encrypt(jwtId), ACCESS_TOKEN_EXPIRES_IN_DURATION);
        return jwtId;
    }

    private enum AccessTokenClaims {
        JWT_ID,
        USER_ID,
        USERNAME,
        EMAIL,
        REAL_EMAIL,
        AUTHORITIES,
        MFA_ENABLED,
        MFA_METHODS,
        ISSUED_AT,
        EXPIRATION
    }

    private Map<String, Object> buildTokenClaims(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var claims = new HashMap<String, Object>();
        claims.put(AccessTokenClaims.JWT_ID.name(), generateJWTId(user));
        claims.put(AccessTokenClaims.USER_ID.name(), user.getId());
        claims.put(AccessTokenClaims.USERNAME.name(), user.getUsername());
        claims.put(AccessTokenClaims.EMAIL.name(), user.getEmail());
        claims.put(AccessTokenClaims.REAL_EMAIL.name(), user.getRealEmail());
        claims.put(AccessTokenClaims.AUTHORITIES.name(), user.getRoles().stream()
                .flatMap(role ->
                        Stream.concat(
                                Stream.of(role.getRoleName()),
                                role.getPermissions().stream().map(PermissionModel::getPermissionName)
                        )
                )
                .collect(Collectors.toSet()));
        claims.put(AccessTokenClaims.MFA_ENABLED.name(), user.isMfaEnabled());
        claims.put(AccessTokenClaims.MFA_METHODS.name(), user.getEnabledMfaMethods().stream()
                .map(UserModel.MfaType::name)
                .collect(Collectors.toSet()));
        claims.put(AccessTokenClaims.ISSUED_AT.name(), Instant.now().toString());
        claims.put(AccessTokenClaims.EXPIRATION.name(), Instant.now().plusSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS).toString());
        return claims;
    }

    private String signToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .signWith(signingKey)
                .compact();
    }

    private String encryptToken(String jws) throws JoseException {
        var jwe = new JsonWebEncryption();
        jwe.setPayload(jws);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jwe.setKey(encryptionKey);
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.A256KW));
        jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512));
        return jwe.getCompactSerialization();
    }

    private UUID generateRefreshToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user);
        var existingEncryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
        if (existingEncryptedRefreshToken != null)
            return refreshTokenRandomConverter.decrypt((String) existingEncryptedRefreshToken, UUID.class);
        var refreshToken = UUID.randomUUID();
        var encryptedRefreshTokenMappingKey = refreshTokenStaticConverter.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
        try {
            redisService.save(encryptedRefreshTokenKey, refreshTokenRandomConverter.encrypt(refreshToken), REFRESH_TOKEN_EXPIRES_IN_DURATION);
            redisService.save(encryptedRefreshTokenMappingKey, refreshTokenRandomConverter.encrypt(user.getId()), REFRESH_TOKEN_EXPIRES_IN_DURATION);
            return refreshToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(encryptedRefreshTokenKey, encryptedRefreshTokenMappingKey));
            throw new RuntimeException("Failed to generate refresh token", ex);
        }
    }

    private String getEncryptedRefreshTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return getEncryptedRefreshTokenKey(user.getId());
    }

    private String getEncryptedRefreshTokenKey(UUID userId) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return refreshTokenStaticConverter.encrypt(REFRESH_TOKEN_PREFIX + userId);
    }

    private Map<String, Object> generateAccessToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        var accessToken = new HashMap<String, Object>();
        accessToken.put("access_token", encryptToken(signToken(buildTokenClaims(user))));
        accessToken.put("expires_in_seconds", ACCESS_TOKEN_EXPIRES_IN_SECONDS);
        accessToken.put("token_type", "Bearer");
        return accessToken;
    }

    public Map<String, Object> generateTokens(UserModel user) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var tokens = generateAccessToken(user);
        tokens.put("refresh_token", generateRefreshToken(user));
        user.recordSuccessfulMfaAttempt();
        user.setLastLoginAt(Instant.now());
        userRepo.save(user);
        return tokens;
    }

    private String decryptToken(String token) throws JoseException {
        var jwe = new JsonWebEncryption();
        jwe.setKey(encryptionKey);
        jwe.setCompactSerialization(token);
        return jwe.getPayload();
    }

    private Claims parseToken(String jws) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(jws)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    public UserDetailsImpl verifyAccessToken(String accessToken) throws JoseException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var claims = parseToken(decryptToken(accessToken));
        if (Instant.parse(claims.get(AccessTokenClaims.ISSUED_AT.name(), String.class)).isAfter(Instant.now()))
            throw new BadRequestException("Invalid token");
        if (Instant.parse(claims.get(AccessTokenClaims.EXPIRATION.name(), String.class)).isBefore(Instant.now()))
            throw new BadRequestException("Invalid token");
        var userId = claims.get(AccessTokenClaims.USER_ID.name(), String.class);
        var encryptedJWTId = redisService.get(jwtStaticConverter.encrypt(JWT_ID_PREFIX + userId));
        if (encryptedJWTId == null) throw new BadRequestException("Invalid token");
        if (!jwtRandomConverter.decrypt((String) encryptedJWTId, String.class).equals(claims.get(AccessTokenClaims.JWT_ID.name(), String.class)))
            throw new BadRequestException("Invalid token");
        var tokenUser = new UserModel();
        tokenUser.setId(UUID.fromString(userId));
        tokenUser.setUsername(claims.get(AccessTokenClaims.USERNAME.name(), String.class));
        tokenUser.setEmail(claims.get(AccessTokenClaims.EMAIL.name(), String.class));
        tokenUser.setRealEmail(claims.get(AccessTokenClaims.REAL_EMAIL.name(), String.class));
        tokenUser.setMfaEnabled(claims.get(AccessTokenClaims.MFA_ENABLED.name(), Boolean.class));
        tokenUser.setEnabledMfaMethods(((List<String>) claims.get(AccessTokenClaims.MFA_METHODS.name(), List.class)).stream().map(UserModel.MfaType::valueOf).collect(Collectors.toSet()));
        return new UserDetailsImpl(tokenUser, ((List<String>) claims.get(AccessTokenClaims.AUTHORITIES.name(), List.class)).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
    }

    private String getEncryptedJWTIdKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return getEncryptedJWTIdKey(user.getId());
    }

    private String getEncryptedJWTIdKey(UUID userId) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return jwtStaticConverter.encrypt(JWT_ID_PREFIX + userId);
    }

    public void revokeAccessToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        redisService.delete(getEncryptedJWTIdKey(user));
    }

    private String getEncryptedRefreshTokenMappingKey(String encryptedRefreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return refreshTokenStaticConverter.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshTokenRandomConverter.decrypt(encryptedRefreshToken, UUID.class));
    }

//    private void revokeRefreshToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
//        var encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user);
//        var encryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
//        if (encryptedRefreshToken != null)
//            redisService.delete(Set.of(encryptedRefreshTokenKey, getEncryptedRefreshTokenMappingKey((String) encryptedRefreshToken)));
//        else redisService.delete(encryptedRefreshTokenKey);
//    }

//    public void revokeTokens(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
//        var encryptedJWTIdKey = getEncryptedJWTIdKey(user);
//        var encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user);
//        var encryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
//        if (encryptedRefreshToken != null)
//            redisService.deleteAll(Set.of(encryptedJWTIdKey, encryptedRefreshTokenKey, getEncryptedRefreshTokenMappingKey((String) encryptedRefreshToken)));
//        else redisService.deleteAll(Set.of(encryptedJWTIdKey, encryptedRefreshTokenKey));
//    }

    public void revokeTokens(Set<UserModel> users) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedKeys = new HashSet<>();
        var encryptedRefreshTokenKeys = new HashSet<>();
        for (var user : users) {
            encryptedKeys.add(getEncryptedJWTIdKey(user));
            encryptedRefreshTokenKeys.add(getEncryptedRefreshTokenKey(user));
        }
        proceedAndRevokeTokens(encryptedKeys, encryptedRefreshTokenKeys);
    }

    private void proceedAndRevokeTokens(Set<Object> encryptedKeys,
                                        Set<Object> encryptedRefreshTokenKeys) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedRefreshTokens = redisService.getAll(encryptedRefreshTokenKeys);
        for (var encryptedRefreshToken : encryptedRefreshTokens) {
            if (encryptedRefreshToken != null)
                encryptedKeys.add(getEncryptedRefreshTokenMappingKey((String) encryptedRefreshToken));
        }
        encryptedKeys.addAll(encryptedRefreshTokenKeys);
        redisService.deleteAll(encryptedKeys);
    }

    public void revokeTokensByUsersIds(Set<UUID> userIds) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedKeys = new HashSet<>();
        var encryptedRefreshTokenKeys = new HashSet<>();
        for (var userId : userIds) {
            encryptedKeys.add(getEncryptedJWTIdKey(userId));
            encryptedRefreshTokenKeys.add(getEncryptedRefreshTokenKey(userId));
        }
        proceedAndRevokeTokens(encryptedKeys, encryptedRefreshTokenKeys);
    }

    public void revokeRefreshToken(String refreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKeyUnencryptedRefreshToken(refreshToken);
        var userId = getUserId(encryptedRefreshTokenMappingKey);
        redisService.delete(encryptedRefreshTokenMappingKey);
        redisService.delete(refreshTokenStaticConverter.encrypt(REFRESH_TOKEN_PREFIX + userId));
    }

    private UUID getUserId(String encryptedRefreshTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedUserId = redisService.get(encryptedRefreshTokenMappingKey);
        if (encryptedUserId != null) return refreshTokenRandomConverter.decrypt((String) encryptedUserId, UUID.class);
        throw new BadRequestException("Invalid refresh token");
    }

    private String getEncryptedRefreshTokenMappingKeyUnencryptedRefreshToken(String refreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return refreshTokenStaticConverter.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
    }

    private UserModel verifyRefreshToken(String refreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var userId = getUserId(getEncryptedRefreshTokenMappingKeyUnencryptedRefreshToken(refreshToken));
        var encryptedRefreshToken = redisService.get(refreshTokenStaticConverter.encrypt(REFRESH_TOKEN_PREFIX + userId));
        if (encryptedRefreshToken != null) {
            if (refreshTokenRandomConverter.decrypt((String) encryptedRefreshToken, String.class).equals(refreshToken))
                return userRepo.findById(userId).orElseThrow(() -> new BadRequestException("Invalid refresh token"));
            throw new BadRequestException("Invalid refresh token");
        }
        throw new BadRequestException("Invalid refresh token");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return generateAccessToken(verifyRefreshToken(refreshToken));
    }
}
