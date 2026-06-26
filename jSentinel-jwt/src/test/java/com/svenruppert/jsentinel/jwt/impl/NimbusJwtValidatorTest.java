package com.svenruppert.jsentinel.jwt.impl;

/*-
 * #%L
 * jSentinel JWT — standardized JWT validation
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.ClaimExpectations;
import com.svenruppert.jsentinel.jwt.api.ClockSkewPolicy;
import com.svenruppert.jsentinel.jwt.api.JwksClient;
import com.svenruppert.jsentinel.jwt.api.JwksRefreshResult;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("NimbusJwtValidator — RS256 against a static key (no mocks)")
class NimbusJwtValidatorTest {

  private static final String ISSUER = "https://idp.example/";
  private static final String AUDIENCE = "api.example";
  private static final String KID = "k1";
  private static final Instant NOW = Instant.parse("2026-06-25T12:00:00Z");

  private RSAKey rsaJwk;
  private NimbusJwtValidator validator;

  @BeforeEach
  void setUp() throws Exception {
    rsaJwk = new RSAKeyGenerator(2048).keyID(KID).generate();
    PublicKey publicKey = rsaJwk.toRSAPublicKey();
    JwksClient staticKeys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(publicKey) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(AUDIENCE), true, false, false, false, ClockSkewPolicy.DEFAULT);
    validator = new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), staticKeys, expectations, () -> NOW);
  }

  private String issue(JWTClaimsSet claims) throws Exception {
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims);
    jwt.sign(new RSASSASigner(rsaJwk));
    return jwt.serialize();
  }

  private JWTClaimsSet.Builder validClaims() {
    return new JWTClaimsSet.Builder()
        .issuer(ISSUER).subject("alice").audience(AUDIENCE)
        .expirationTime(Date.from(NOW.plusSeconds(300)));
  }

  @Test
  @DisplayName("a valid RS256 token is accepted and exposes its claims")
  void acceptsValid() throws Exception {
    Result<ValidatedJwt, JwtValidationError> result = validator.validate(issue(validClaims().build()));
    ValidatedJwt v = result.toOptional().orElseThrow(
        () -> new AssertionError("expected success, got " + result));
    assertEquals(Optional.of(ISSUER), v.issuer());
    assertEquals(Optional.of("alice"), v.subject());
    assertEquals("RS256", v.header().alg());
  }

  @Test
  @DisplayName("an expired token is rejected")
  void rejectsExpired() throws Exception {
    String token = issue(validClaims().expirationTime(Date.from(NOW.minusSeconds(60))).build());
    JwtValidationError error = error(token);
    assertInstanceOf(JwtValidationError.Expired.class, error);
    assertEquals("jwt/expired", error.code());
  }

  @Test
  @DisplayName("a wrong issuer is rejected")
  void rejectsWrongIssuer() throws Exception {
    String token = issue(validClaims().issuer("https://evil.example/").build());
    JwtValidationError error = error(token);
    assertEquals("claims/issuer-mismatch", error.code());
  }

  @Test
  @DisplayName("an audience outside the accepted set is rejected")
  void rejectsAudienceMismatch() throws Exception {
    String token = issue(validClaims().audience("other.example").build());
    JwtValidationError error = error(token);
    assertEquals("claims/audience-mismatch", error.code());
  }

  @Test
  @DisplayName("a tampered payload fails signature verification")
  void rejectsTamperedSignature() throws Exception {
    String token = issue(validClaims().build());
    String[] parts = token.split("\\.");
    // flip the payload to a different (validly-encoded) claim set, keep the signature
    String forgedPayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
        new JWTClaimsSet.Builder().issuer(ISSUER).subject("mallory").audience(AUDIENCE)
            .expirationTime(Date.from(NOW.plusSeconds(300))).build()
            .toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String tampered = parts[0] + "." + forgedPayload + "." + parts[2];
    assertInstanceOf(JwtValidationError.SignatureInvalid.class, error(tampered));
  }

  @Test
  @DisplayName("an unknown kid is rejected")
  void rejectsUnknownKid() throws Exception {
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("other-kid").build(), validClaims().build());
    jwt.sign(new RSASSASigner(rsaJwk));
    assertInstanceOf(JwtValidationError.UnknownKid.class, error(jwt.serialize()));
  }

  @Test
  @DisplayName("a five-segment JWE is rejected as unsupported")
  void rejectsJwe() {
    assertInstanceOf(JwtValidationError.JweNotSupported.class, error("a.b.c.d.e"));
  }

  @Test
  @DisplayName("a two-segment token is malformed")
  void rejectsMalformed() {
    assertInstanceOf(JwtValidationError.MalformedJwt.class, error("a.b"));
  }

  private JwtValidationError error(String token) {
    Result<ValidatedJwt, JwtValidationError> result = validator.validate(token);
    assertTrue(result.toOptional().isEmpty(), "expected failure for token");
    // Result has no direct getError; re-derive via a failure-only mapping.
    return result.map(v -> (JwtValidationError) null).getOrElse(e -> e);
  }

  // ── F4 (V00.76.10): optional typ-header validation (RFC 8725 §3.11) ─────

  private NimbusJwtValidator validatorExpectingTyp(String expectedTyp) throws Exception {
    PublicKey publicKey = rsaJwk.toRSAPublicKey();
    JwksClient staticKeys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(publicKey) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(AUDIENCE), true, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.of(expectedTyp));
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), staticKeys, expectations, () -> NOW);
  }

  private String issueWithTyp(JWTClaimsSet claims, String typ) throws Exception {
    JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID);
    if (typ != null) {
      header.type(new com.nimbusds.jose.JOSEObjectType(typ));
    }
    SignedJWT jwt = new SignedJWT(header.build(), claims);
    jwt.sign(new RSASSASigner(rsaJwk));
    return jwt.serialize();
  }

  private static JwtValidationError errorOf(NimbusJwtValidator v, String token) {
    Result<ValidatedJwt, JwtValidationError> result = v.validate(token);
    assertTrue(result.toOptional().isEmpty(), "expected failure for token");
    return result.map(x -> (JwtValidationError) null).getOrElse(e -> e);
  }

  @Test
  @DisplayName("F4: a matching typ header is accepted (application/ prefix tolerated)")
  void typMatchAccepted() throws Exception {
    NimbusJwtValidator v = validatorExpectingTyp("at+jwt");
    assertTrue(v.validate(issueWithTyp(validClaims().build(), "at+jwt")).toOptional().isPresent(),
        "an exact typ match must pass");
    assertTrue(v.validate(issueWithTyp(validClaims().build(), "application/at+jwt")).toOptional().isPresent(),
        "the application/ prefix and case must be tolerated");
    assertTrue(v.validate(issueWithTyp(validClaims().build(), "AT+JWT")).toOptional().isPresent(),
        "the comparison is case-insensitive");
  }

  @Test
  @DisplayName("F4: a mismatching typ header is rejected with claims/typ-mismatch")
  void typMismatchRejected() throws Exception {
    NimbusJwtValidator v = validatorExpectingTyp("at+jwt");
    JwtValidationError error = errorOf(v, issueWithTyp(validClaims().build(), "JWT"));
    assertEquals("claims/typ-mismatch", error.code());
  }

  @Test
  @DisplayName("F4: a missing typ header is rejected when a type is expected")
  void typMissingRejectedWhenExpected() throws Exception {
    NimbusJwtValidator v = validatorExpectingTyp("at+jwt");
    JwtValidationError error = errorOf(v, issueWithTyp(validClaims().build(), null));
    assertEquals("claims/typ-mismatch", error.code());
  }

  @Test
  @DisplayName("F4: default (no expected typ) does not check the typ header")
  void typNotCheckedByDefault() throws Exception {
    // the default `validator` (setUp) has no expectedTyp — any/no typ is accepted
    assertTrue(validator.validate(issueWithTyp(validClaims().build(), "anything+jwt")).toOptional().isPresent(),
        "without an expected typ, the header must not be checked");
    assertTrue(validator.validate(issueWithTyp(validClaims().build(), null)).toOptional().isPresent(),
        "without an expected typ, a missing typ header must be accepted");
  }
}
