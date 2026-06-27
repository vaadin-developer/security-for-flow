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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.ClaimExpectations;
import com.svenruppert.jsentinel.jwt.api.ClockSkewPolicy;
import com.svenruppert.jsentinel.jwt.api.JweAlgorithmAllowList;
import com.svenruppert.jsentinel.jwt.api.JweDecodingError;
import com.svenruppert.jsentinel.jwt.api.JwksClient;
import com.svenruppert.jsentinel.jwt.api.JwksRefreshResult;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;

import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * No-mock JWE decoding: real RSA encryption + signing keys, real Nimbus encrypt/decrypt,
 * real {@link NimbusJwtValidator} for the inner JWS. Proves a JWE(JWS) round-trips and
 * each RFC 7516 reject path fires (downgrade alg/enc, tampered ciphertext, wrong key).
 */
@DisplayName("JWE decoding — NimbusJweDecoder + JweUnwrappingJwtValidator (RFC 7516)")
class JweDecodingTest {

  private static final String ISSUER = "https://op.example.com";
  private static final String AUD = "rp-client";
  private static final String SIGKID = "sig-1";
  private static final Instant NOW = Instant.parse("2026-06-27T12:00:00Z");

  private final RSAKey signKey = gen(SIGKID);
  private final RSAKey encKey = gen("enc-1");

  private static RSAKey gen(String kid) {
    try {
      return new RSAKeyGenerator(2048).keyID(kid).generate();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private JwtValidator innerValidator() {
    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        try {
          return SIGKID.equals(kid) ? Optional.of(signKey.toRSAPublicKey()) : Optional.empty();
        } catch (Exception e) {
          throw new IllegalStateException(e);
        }
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(AUD), false, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty());
    return new NimbusJwtValidator(AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, () -> NOW);
  }

  private String innerJws() {
    try {
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(ISSUER).audience(AUD).subject("alice").issueTime(Date.from(NOW)).build();
      SignedJWT jws = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(SIGKID).build(), claims);
      jws.sign(new RSASSASigner(signKey));
      return jws.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private String encrypt(JWEAlgorithm alg, EncryptionMethod enc, RSAPublicKey to) {
    try {
      JWEObject jwe = new JWEObject(
          new JWEHeader.Builder(alg, enc).contentType("JWT").build(),
          new Payload(innerJws()));
      jwe.encrypt(new RSAEncrypter(to));
      return jwe.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private RSAPublicKey encPub() {
    try {
      return encKey.toRSAPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private RSAPrivateKey encPriv() {
    try {
      return encKey.toRSAPrivateKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  @DisplayName("a JWE(JWS) validates end-to-end through the unwrapping decorator")
  void jweRoundTrip() {
    String jwe = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, encPub());
    JweUnwrappingJwtValidator validator = new JweUnwrappingJwtValidator(
        innerValidator(), new NimbusJweDecoder(JweAlgorithmAllowList.defaults()), encPriv());
    assertTrue(validator.validate(jwe).isSuccess(), "decrypted + validated id token");
  }

  @Test
  @DisplayName("a plain three-segment JWS passes straight through the decorator")
  void plainJwsPassThrough() {
    JweUnwrappingJwtValidator validator = new JweUnwrappingJwtValidator(
        innerValidator(), new NimbusJweDecoder(JweAlgorithmAllowList.defaults()), encPriv());
    assertTrue(validator.validate(innerJws()).isSuccess());
  }

  @Test
  @DisplayName("a non-allow-listed content-encryption (A128CBC-HS256) is rejected")
  void encNotAllowed() {
    String jwe = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256, encPub());
    JweDecodingError err = new NimbusJweDecoder(JweAlgorithmAllowList.defaults())
        .decode(jwe, encPriv()).fold(ok -> null, e -> e);
    assertInstanceOf(JweDecodingError.UnsupportedEncryption.class, err);
  }

  @Test
  @DisplayName("a downgrade key-management algorithm (RSA1_5) is rejected before decryption")
  void algDowngradeRejected() {
    @SuppressWarnings("deprecation")
    String jwe = encrypt(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM, encPub());
    JweDecodingError err = new NimbusJweDecoder(JweAlgorithmAllowList.defaults())
        .decode(jwe, encPriv()).fold(ok -> null, e -> e);
    assertInstanceOf(JweDecodingError.UnsupportedAlgorithm.class, err);
  }

  @Test
  @DisplayName("a wrong decryption key fails the auth tag")
  void wrongKeyRejected() {
    String jwe = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, encPub());
    RSAPrivateKey wrong;
    try {
      wrong = gen("other").toRSAPrivateKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    JweDecodingError err = new NimbusJweDecoder(JweAlgorithmAllowList.defaults())
        .decode(jwe, wrong).fold(ok -> null, e -> e);
    assertInstanceOf(JweDecodingError.DecryptionFailed.class, err);
  }

  @Test
  @DisplayName("a non-JWE three-segment input is reported as not-a-JWE by the decoder")
  void notJwe() {
    JweDecodingError err = new NimbusJweDecoder(JweAlgorithmAllowList.defaults())
        .decode(innerJws(), encPriv()).fold(ok -> null, e -> e);
    assertInstanceOf(JweDecodingError.NotJwe.class, err);
  }

  @Test
  @DisplayName("the FIPS allow-list permits A256GCM but not A128GCM")
  void fipsAllowList() {
    assertTrue(JweAlgorithmAllowList.fips().allowsContentEncryption("A256GCM"));
    assertEquals(false, JweAlgorithmAllowList.fips().allowsContentEncryption("A128GCM"));
  }
}
