/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.impl.NimbusJwtValidator;
import eu.jsentinel.jcustos.oidc.api.IdTokenExpectations;
import eu.jsentinel.jcustos.oidc.api.IdTokenValidationError;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DefaultIdTokenValidator — composes a real JwtValidator + OIDC checks (no mocks)")
class DefaultIdTokenValidatorTest {

  private static final String ISSUER = "https://idp.example/";
  private static final String CLIENT = "rp-client";
  private static final String KID = "k1";
  private static final Instant NOW = Instant.parse("2026-06-26T12:00:00Z");

  private final RSAKey rsa = newKey();
  private final DefaultIdTokenValidator validator = new DefaultIdTokenValidator(
      jwtValidator(publicKey()), () -> NOW);

  private static RSAKey newKey() {
    try {
      return new RSAKeyGenerator(2048).keyID(KID).generate();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private PublicKey publicKey() {
    try {
      return rsa.toPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** A real Nimbus JWT validator whose JWKS resolves KID to the test key. */
  private static NimbusJwtValidator jwtValidator(PublicKey key) {
    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(key) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(CLIENT), true, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty());
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, () -> NOW);
  }

  private String sign(JWTClaimsSet.Builder claims) {
    try {
      claims.issuer(ISSUER).subject("alice").expirationTime(Date.from(NOW.plusSeconds(300)));
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(),
          claims.build());
      jwt.sign(new RSASSASigner(rsa));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String atHash(String accessToken) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(d, 0, d.length / 2));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private IdTokenValidationError errorOf(Result<ValidatedIdToken, IdTokenValidationError> r) {
    assertTrue(r.toOptional().isEmpty(), "expected validation failure, got success");
    return r.fold(v -> null, e -> e);
  }

  @Test
  @DisplayName("JS-SEC-007: OIDC-layer backstop rejects a wrong audience even when the composed JwtValidator does not check aud")
  void backstopRejectsWrongAudience() {
    // A JwtValidator with NO audience expectation (empty acceptedAudiences) —
    // the mis-wiring the OIDC-layer backstop defends against. It still checks
    // the issuer, isolating the audience path.
    JwksClient keys = new JwksClient() {
      @Override public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(publicKey()) : Optional.empty();
      }
      @Override public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations laxAud = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(), true, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty());
    DefaultIdTokenValidator lax = new DefaultIdTokenValidator(
        new NimbusJwtValidator(AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, laxAud, () -> NOW),
        () -> NOW);

    // token for a DIFFERENT client — the lax JWT layer accepts it, the OIDC
    // backstop must reject it (JS-SEC-007).
    String token = sign(new JWTClaimsSet.Builder().audience("victim-rp-b").claim("nonce", "n-1"));
    assertEquals("oidc/audience-mismatch",
        errorOf(lax.validate(token, IdTokenExpectations.of(ISSUER, CLIENT, Optional.of("n-1")))).code());
  }

  @Test
  @DisplayName("a well-formed ID token (nonce, single aud) validates and surfaces the OIDC claims")
  void validToken() {
    String token = sign(new JWTClaimsSet.Builder().audience(CLIENT)
        .claim("nonce", "n-1").claim("acr", "mfa").claim("amr", List.of("pwd", "otp")));
    ValidatedIdToken vit = validator.validate(token,
        IdTokenExpectations.of(ISSUER, CLIENT, Optional.of("n-1"))).toOptional().orElseThrow();
    assertEquals(Optional.of("n-1"), vit.nonce());
    assertEquals(Optional.of("mfa"), vit.acr());
    assertEquals(List.of("pwd", "otp"), vit.amr());
    assertEquals(Optional.of("alice"), vit.subject());
  }

  @Test
  @DisplayName("a nonce mismatch is rejected")
  void nonceMismatch() {
    String token = sign(new JWTClaimsSet.Builder().audience(CLIENT).claim("nonce", "attacker"));
    assertInstanceOf(IdTokenValidationError.NonceMismatch.class,
        errorOf(validator.validate(token, IdTokenExpectations.of(ISSUER, CLIENT, Optional.of("n-1")))));
  }

  @Test
  @DisplayName("multiple audiences without azp is rejected (oidc/azp-invalid)")
  void azpMissingWithMultipleAudiences() {
    String token = sign(new JWTClaimsSet.Builder().audience(List.of(CLIENT, "other-rp"))
        .claim("nonce", "n-1"));
    assertInstanceOf(IdTokenValidationError.AuthorizedPartyInvalid.class,
        errorOf(validator.validate(token, IdTokenExpectations.of(ISSUER, CLIENT, Optional.of("n-1")))));
  }

  @Test
  @DisplayName("multiple audiences with a correct azp validates")
  void azpPresentWithMultipleAudiences() {
    String token = sign(new JWTClaimsSet.Builder().audience(List.of(CLIENT, "other-rp"))
        .claim("nonce", "n-1").claim("azp", CLIENT));
    assertTrue(validator.validate(token,
        IdTokenExpectations.of(ISSUER, CLIENT, Optional.of("n-1"))).toOptional().isPresent());
  }

  @Test
  @DisplayName("a matching at_hash validates; a wrong at_hash is rejected")
  void atHashCheck() {
    String accessToken = "ACCESS-TOKEN-xyz";
    String good = sign(new JWTClaimsSet.Builder().audience(CLIENT).claim("at_hash", atHash(accessToken)));
    IdTokenExpectations exp = new IdTokenExpectations(ISSUER, CLIENT, Optional.empty(),
        Optional.of(accessToken), Optional.empty(), Optional.empty(), Set.of(),
        IdTokenExpectations.DEFAULT_CLOCK_SKEW);
    assertTrue(validator.validate(good, exp).toOptional().isPresent());

    String bad = sign(new JWTClaimsSet.Builder().audience(CLIENT).claim("at_hash", atHash("WRONG")));
    assertInstanceOf(IdTokenValidationError.AccessTokenHashMismatch.class,
        errorOf(validator.validate(bad, exp)));
  }

  @Test
  @DisplayName("an auth_time older than max_age is rejected (stale)")
  void authTimeStale() {
    String token = sign(new JWTClaimsSet.Builder().audience(CLIENT)
        .claim("auth_time", NOW.minusSeconds(1000).getEpochSecond()));
    IdTokenExpectations exp = new IdTokenExpectations(ISSUER, CLIENT, Optional.empty(),
        Optional.empty(), Optional.empty(), Optional.of(Duration.ofSeconds(300)), Set.of(),
        IdTokenExpectations.DEFAULT_CLOCK_SKEW);
    assertInstanceOf(IdTokenValidationError.AuthTimeStale.class, errorOf(validator.validate(token, exp)));
  }

  @Test
  @DisplayName("an acr outside the requested set is rejected")
  void acrUnsatisfied() {
    String token = sign(new JWTClaimsSet.Builder().audience(CLIENT).claim("acr", "pwd"));
    IdTokenExpectations exp = new IdTokenExpectations(ISSUER, CLIENT, Optional.empty(),
        Optional.empty(), Optional.empty(), Optional.empty(), Set.of("mfa"),
        IdTokenExpectations.DEFAULT_CLOCK_SKEW);
    assertInstanceOf(IdTokenValidationError.AcrUnsatisfied.class, errorOf(validator.validate(token, exp)));
  }

  @Test
  @DisplayName("a bad signature (wrong key) maps to JwtInvalid")
  void badSignatureMapsToJwtInvalid() {
    RSAKey otherKey = newKey();
    DefaultIdTokenValidator v = new DefaultIdTokenValidator(jwtValidator(pub(otherKey)), () -> NOW);
    String token = sign(new JWTClaimsSet.Builder().audience(CLIENT).claim("nonce", "n-1"));
    assertInstanceOf(IdTokenValidationError.JwtInvalid.class,
        errorOf(v.validate(token, IdTokenExpectations.of(ISSUER, CLIENT, Optional.of("n-1")))));
  }

  private static PublicKey pub(RSAKey k) {
    try {
      return k.toPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
