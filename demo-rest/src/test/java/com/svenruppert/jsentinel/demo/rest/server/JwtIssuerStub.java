package com.svenruppert.jsentinel.demo.rest.server;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.ClaimExpectations;
import com.svenruppert.jsentinel.jwt.api.ClockSkewPolicy;
import com.svenruppert.jsentinel.jwt.api.JwksClient;
import com.svenruppert.jsentinel.jwt.api.JwksRefreshResult;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;
import com.svenruppert.jsentinel.jwt.impl.NimbusJwtValidator;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

/**
 * Test-only in-process IDP: signs RS256 JWTs and exposes a matching
 * {@link JwtValidator}. Lives in {@code demo-rest} test scope (not the shared
 * artifact) so no JOSE library reaches the deployed demo.
 */
final class JwtIssuerStub {

  static final String ISSUER = "https://demo-idp.example/";
  static final String AUDIENCE = "demo-rest";
  private static final String KID = "demo-kid";

  private final RSAKey rsaJwk;

  JwtIssuerStub() throws Exception {
    this.rsaJwk = new RSAKeyGenerator(2048).keyID(KID).generate();
  }

  String issue(String subject, Instant now) throws Exception {
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(ISSUER).subject(subject).audience(AUDIENCE)
        .expirationTime(Date.from(now.plusSeconds(300)))
        .build();
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims);
    jwt.sign(new RSASSASigner(rsaJwk));
    return jwt.serialize();
  }

  JwtValidator validator(Instant now) throws Exception {
    PublicKey publicKey = rsaJwk.toRSAPublicKey();
    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(publicKey) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, now, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(AUDIENCE), true, false, false, false, ClockSkewPolicy.DEFAULT);
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, () -> now);
  }
}
