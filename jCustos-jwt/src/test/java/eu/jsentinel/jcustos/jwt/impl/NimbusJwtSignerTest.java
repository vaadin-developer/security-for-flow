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
package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtSigningException;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("NimbusJwtSigner — real signing round-trips through NimbusJwtValidator (no mocks)")
class NimbusJwtSignerTest {

  private static final Instant NOW = Instant.parse("2026-06-26T12:00:00Z");
  private static final String ISSUER = "client-x";
  private static final String AUDIENCE = "https://idp.example/token";

  private final NimbusJwtSigner signer = new NimbusJwtSigner();

  private Map<String, Object> clientAssertionClaims() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", ISSUER);
    claims.put("sub", ISSUER);
    claims.put("aud", AUDIENCE);
    claims.put("jti", "assertion-1");
    claims.put("iat", NOW.getEpochSecond());
    claims.put("exp", NOW.plusSeconds(60).getEpochSecond());
    return claims;
  }

  /** Signs the claims with the key, then validates the JWS with the public key. */
  private ValidatedJwt signAndValidate(JwsAlgorithm alg, KeyPair keyPair, String kid) {
    String compact = signer.sign(clientAssertionClaims(),
        new JwtSigningKey(keyPair.getPrivate(), alg, Optional.of(kid)));

    JwksClient staticKey = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String k, JwsAlgorithm a) {
        return kid.equals(k) ? Optional.of(keyPair.getPublic()) : Optional.empty();
      }
      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(AUDIENCE), true, false, false, false, ClockSkewPolicy.DEFAULT);
    NimbusJwtValidator validator = new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), staticKey, expectations, () -> NOW);

    Result<ValidatedJwt, JwtValidationError> result = validator.validate(compact);
    return result.toOptional().orElseThrow(
        () -> new AssertionError("expected the signed assertion to validate, got " + result));
  }

  @Test
  @DisplayName("RS256: a signed client assertion validates and round-trips its claims")
  void rs256RoundTrip() throws Exception {
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    rsa.initialize(2048);
    ValidatedJwt v = signAndValidate(JwsAlgorithm.RS256, rsa.generateKeyPair(), "rsa-1");
    assertEquals(Optional.of(ISSUER), v.issuer());
    assertEquals(Optional.of(ISSUER), v.subject());
    assertEquals("RS256", v.header().alg());
    assertEquals(Optional.of("rsa-1"), v.header().kid());
  }

  @Test
  @DisplayName("ES256: a signed client assertion validates")
  void es256RoundTrip() throws Exception {
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    ValidatedJwt v = signAndValidate(JwsAlgorithm.ES256, ec.generateKeyPair(), "ec-1");
    assertEquals("ES256", v.header().alg());
    assertEquals(Optional.of(ISSUER), v.issuer());
  }

  @Test
  @DisplayName("EdDSA: a signed client assertion validates (JDK Ed25519, no Tink)")
  void eddsaRoundTrip() throws Exception {
    KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    ValidatedJwt v = signAndValidate(JwsAlgorithm.EdDSA, ed, "ed-1");
    assertEquals("EdDSA", v.header().alg());
    assertEquals(Optional.of(ISSUER), v.issuer());
  }

  @Test
  @DisplayName("a tampered signed assertion fails validation (signature really covers the payload)")
  void tamperedFailsValidation() throws Exception {
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    rsa.initialize(2048);
    KeyPair keyPair = rsa.generateKeyPair();
    String compact = signer.sign(clientAssertionClaims(),
        new JwtSigningKey(keyPair.getPrivate(), JwsAlgorithm.RS256, Optional.of("rsa-1")));
    // flip a character in the payload segment
    String[] parts = compact.split("\\.");
    parts[1] = parts[1].substring(0, parts[1].length() - 2)
        + (parts[1].endsWith("A") ? "B" : "A");
    String tampered = parts[0] + "." + parts[1] + "." + parts[2];

    JwksClient staticKey = new JwksClient() {
      @Override public Optional<PublicKey> findKey(String k, JwsAlgorithm a) { return Optional.of(keyPair.getPublic()); }
      @Override public JwksRefreshResult refreshOnce() { return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty()); }
    };
    NimbusJwtValidator validator = new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), staticKey,
        new ClaimExpectations(Optional.of(ISSUER), Set.of(AUDIENCE), true, false, false, false, ClockSkewPolicy.DEFAULT),
        () -> NOW);
    assertTrue(validator.validate(tampered).toOptional().isEmpty(),
        "a tampered assertion must not validate");
  }

  @Test
  @DisplayName("a key that does not match the algorithm family is rejected")
  void keyFamilyMismatchRejected() throws Exception {
    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ec = ecGen.generateKeyPair();
    // EC key with an RSA algorithm -> signing must refuse
    JwtSigningException ex = assertThrows(JwtSigningException.class, () ->
        signer.sign(clientAssertionClaims(),
            new JwtSigningKey(ec.getPrivate(), JwsAlgorithm.RS256, Optional.empty())));
    assertEquals("jwt-signing/key-algorithm-mismatch", ex.code());
  }
}
