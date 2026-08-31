package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("NimbusJwtValidator — algorithm matrix + confusion defence (no mocks)")
class NimbusJwtValidatorAlgorithmTest {

  private static final String ISSUER = "https://idp.example/";
  private static final String AUDIENCE = "api.example";
  private static final String KID = "k1";
  private static final Instant NOW = Instant.parse("2026-06-25T12:00:00Z");

  private static JWTClaimsSet claims() {
    return new JWTClaimsSet.Builder().issuer(ISSUER).subject("alice").audience(AUDIENCE)
        .expirationTime(Date.from(NOW.plusSeconds(300))).build();
  }

  /** Validator whose JWKS resolves {@link #KID} to the given key (or nothing for other kids). */
  private static NimbusJwtValidator validatorReturning(PublicKey keyForKid) {
    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(keyForKid) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(AUDIENCE), true, false, false, false, ClockSkewPolicy.DEFAULT);
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, () -> NOW);
  }

  private static JwtValidationError error(NimbusJwtValidator validator, String token) {
    Result<ValidatedJwt, JwtValidationError> result = validator.validate(token);
    assertTrue(result.toOptional().isEmpty(), "expected failure");
    return result.map(v -> (JwtValidationError) null).getOrElse(e -> e);
  }

  // ---- positive: the full asymmetric matrix verifies ----

  @Test
  @DisplayName("ES256 verifies against the matching EC key")
  void acceptsEs256() throws Exception {
    ECKey ec = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(KID).build(), claims());
    jwt.sign(new ECDSASigner(ec));
    assertTrue(validatorReturning(ec.toECPublicKey()).validate(jwt.serialize()).toOptional().isPresent());
  }

  @Test
  @DisplayName("EdDSA (Ed25519) verifies against the matching key (JDK signer, no Tink)")
  void acceptsEdDsa() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String headerB64 = Base64URL.encode(
        "{\"alg\":\"EdDSA\",\"kid\":\"k1\"}".getBytes(StandardCharsets.UTF_8)).toString();
    String payloadB64 = Base64URL.encode(
        claims().toString().getBytes(StandardCharsets.UTF_8)).toString();
    String signingInput = headerB64 + "." + payloadB64;
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(kp.getPrivate());
    signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
    String token = signingInput + "." + Base64URL.encode(signer.sign());
    assertTrue(validatorReturning(kp.getPublic()).validate(token).toOptional().isPresent());
  }

  @Test
  @DisplayName("PS256 verifies against the matching RSA key")
  void acceptsPs256() throws Exception {
    RSAKey rsa = new RSAKeyGenerator(2048).keyID(KID).generate();
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(KID).build(), claims());
    jwt.sign(new RSASSASigner(rsa));
    assertTrue(validatorReturning(rsa.toRSAPublicKey()).validate(jwt.serialize()).toOptional().isPresent());
  }

  // ---- adversarial: confusion vectors are hard-rejected ----

  @Test
  @DisplayName("alg:none is rejected before any key lookup")
  void rejectsAlgNone() throws Exception {
    RSAKey rsa = new RSAKeyGenerator(2048).keyID(KID).generate();
    String header = Base64URL.encode("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)).toString();
    String payload = Base64URL.encode("{\"sub\":\"alice\"}".getBytes(StandardCharsets.UTF_8)).toString();
    String none = header + "." + payload + ".";
    JwtValidationError error = error(validatorReturning(rsa.toRSAPublicKey()), none);
    assertInstanceOf(JwtValidationError.UnsupportedAlgorithm.class, error);
    assertEquals("jwt/algorithm-none-attempted", error.code());
  }

  @Test
  @DisplayName("HS256 signed with the RSA public key as the HMAC secret is rejected (not allow-listed)")
  void rejectsHs256WithRsaPublicKey() throws Exception {
    RSAKey rsa = new RSAKeyGenerator(2048).keyID(KID).generate();
    byte[] secret = rsa.toRSAPublicKey().getEncoded(); // the classic confusion secret
    SignedJWT hs = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KID).build(), claims());
    hs.sign(new MACSigner(secret));
    JwtValidationError error = error(validatorReturning(rsa.toRSAPublicKey()), hs.serialize());
    assertInstanceOf(JwtValidationError.UnsupportedAlgorithm.class, error);
    assertEquals("jwt/algorithm-not-in-allow-list", error.code());
  }

  @Test
  @DisplayName("ES256 header whose kid resolves to an RSA key is rejected as algorithm-confusion")
  void rejectsEs256WithRsaKey() throws Exception {
    ECKey ec = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
    RSAKey rsa = new RSAKeyGenerator(2048).keyID(KID).generate();
    SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(KID).build(), claims());
    jwt.sign(new ECDSASigner(ec));
    // the validator resolves the kid to an RSA key — family mismatch must be caught
    JwtValidationError error = error(validatorReturning(rsa.toRSAPublicKey()), jwt.serialize());
    assertInstanceOf(JwtValidationError.UnsupportedAlgorithm.class, error);
    assertEquals("jwt/algorithm-confusion-suspected", error.code());
  }
}
