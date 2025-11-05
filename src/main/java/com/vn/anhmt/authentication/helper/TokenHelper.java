package com.vn.anhmt.authentication.helper;

import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenHelper {

    public static final String AUTHORIZATION = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String TOKEN_TYPE_HINT = "token_type_hint";
    public static final String TOKEN_ID = "jti";

    private final KeyPair keyPair;

    public String generateAccessToken(String username, UUID tokenId) {
        return createToken(
                username,
                OAuth2TokenType.ACCESS_TOKEN.getValue(),
                Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)));
    }

    public String generateRefreshToken(String username, UUID tokenId) {
        return createToken(
                username,
                OAuth2TokenType.REFRESH_TOKEN.getValue(),
                Date.from(Instant.now().plus(7, ChronoUnit.MINUTES)));
    }

    public String extractUsername(String token) {
        return (String) extractClaims(token).get(SUBJECT);
    }

    public String extractTokenId(String token) {
        return (String) extractClaims(token).get(TOKEN_ID);
    }

    public String extractTokenType(String token) {
        return (String) extractClaims(token).get(TOKEN_TYPE_HINT);
    }

    private Map<String, Object> extractClaims(String tokenString) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(tokenString);

            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());

            if (signedJWT.verify(verifier)) {
                return signedJWT.getJWTClaimsSet().getClaims();
            } else {
                throw new IllegalArgumentException("Token invalid");
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private String createToken(String username, String tokenType, Date date) {
        JWSHeader header = new JWSHeader((JWSAlgorithm.HS512));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer(username)
                .issueTime(new Date(System.currentTimeMillis()))
                .expirationTime(date)
                .claim(TOKEN_TYPE_HINT, tokenType)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalArgumentException(e);
        }

        return signedJWT.serialize();
    }
}
