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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.jwt.api.AlgorithmAllowList;
import com.svenruppert.jsentinel.jwt.api.ClaimExpectations;
import com.svenruppert.jsentinel.jwt.api.JoseHeader;
import com.svenruppert.jsentinel.jwt.api.JwksClient;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Nimbus JOSE+JWT-backed {@link JwtValidator} implementing the Konzept §6.3
 * pipeline: format → header → allow-list → key lookup → algorithm-family check →
 * signature → claims. Expected failures are returned as {@link JwtValidationError}
 * in the {@link Result}; the raw token is never logged.
 *
 * <p>V00.76 is asymmetric-only. RSA ({@code RS*}/{@code PS*}) and EC ({@code ES*})
 * verifiers are built directly from the resolved {@link PublicKey}; EdDSA verifier
 * wiring is completed in a follow-up within the cycle.
 *
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public final class NimbusJwtValidator implements JwtValidator {

  private final AlgorithmAllowList allowList;
  private final JwksClient jwksClient;
  private final ClaimExpectations expectations;
  private final Supplier<Instant> clock;

  public NimbusJwtValidator(AlgorithmAllowList allowList, JwksClient jwksClient,
      ClaimExpectations expectations, Supplier<Instant> clock) {
    this.allowList = Objects.requireNonNull(allowList, "allowList");
    this.jwksClient = Objects.requireNonNull(jwksClient, "jwksClient");
    this.expectations = Objects.requireNonNull(expectations, "expectations");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  public NimbusJwtValidator(AlgorithmAllowList allowList, JwksClient jwksClient,
      ClaimExpectations expectations) {
    this(allowList, jwksClient, expectations, Instant::now);
  }

  @Override
  public Result<ValidatedJwt, JwtValidationError> validate(String compactJwt) {
    if (compactJwt == null || compactJwt.isBlank()) {
      return Result.failure(new JwtValidationError.MalformedJwt("compact JWT is blank"));
    }
    // 1. Format check — three segments for JWS, five for JWE.
    int segments = countSegments(compactJwt);
    if (segments == 5) {
      return Result.failure(new JwtValidationError.JweNotSupported(
          "encrypted JWT (JWE) is not supported in V00.76"));
    }
    if (segments != 3) {
      return Result.failure(new JwtValidationError.MalformedJwt(
          "compact JWT does not have three segments"));
    }

    // 2. Header parse — alg/kid are untrusted until the signature verifies.
    SignedJWT jwt;
    String headerAlg;
    String kid;
    try {
      jwt = SignedJWT.parse(compactJwt);
      headerAlg = jwt.getHeader().getAlgorithm() == null
          ? null : jwt.getHeader().getAlgorithm().getName();
      kid = jwt.getHeader().getKeyID();
    } catch (ParseException e) {
      return Result.failure(new JwtValidationError.MalformedJwt("JOSE header is not parseable"));
    }

    // 3. Allow-list check — alg:none and any non-listed algorithm are rejected here.
    if ("none".equalsIgnoreCase(headerAlg)) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-none-attempted", "alg:none is never accepted"));
    }
    Optional<JwsAlgorithm> algorithm = JwsAlgorithm.fromHeader(headerAlg);
    if (algorithm.isEmpty() || !allowList.allows(algorithm.get())) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-not-in-allow-list",
          "header algorithm is not in the allow-list"));
    }
    JwsAlgorithm alg = algorithm.get();

    // 4. Key lookup — a kid miss triggers at most one refresh inside the client.
    Optional<PublicKey> key = jwksClient.findKey(kid, alg);
    if (key.isEmpty()) {
      return Result.failure(new JwtValidationError.UnknownKid(
          "no key for the presented kid"));
    }

    // 5. Algorithm-family check — the resolved key type must match the alg family.
    //    This is the algorithm-confusion defence: an HS alg can never reach here
    //    (not allow-listed), and an RS/PS/ES alg must pair with the matching key.
    if (!familyMatches(alg, key.get())) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-confusion-suspected",
          "algorithm family does not match the resolved key type"));
    }

    // 6. Signature verification.
    Optional<JWSVerifier> verifier = verifierFor(alg, key.get());
    if (verifier.isEmpty()) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-not-in-allow-list",
          "no verifier available for the algorithm"));
    }
    boolean signatureValid;
    try {
      signatureValid = jwt.verify(verifier.get());
    } catch (RuntimeException | com.nimbusds.jose.JOSEException e) {
      return Result.failure(new JwtValidationError.SignatureInvalid("signature verification failed"));
    }
    if (!signatureValid) {
      return Result.failure(new JwtValidationError.SignatureInvalid("signature does not verify"));
    }

    // 7. Claims validation.
    JWTClaimsSet claims;
    try {
      claims = jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      return Result.failure(new JwtValidationError.MalformedJwt("claims set is not parseable"));
    }
    Optional<JwtValidationError> claimError = validateClaims(claims);
    if (claimError.isPresent()) {
      return Result.failure(claimError.get());
    }

    // 8. Success.
    JoseHeader header = new JoseHeader(headerAlg, Optional.ofNullable(kid),
        Optional.ofNullable(jwt.getHeader().getType()).map(Object::toString));
    return Result.success(new ValidatedJwt(compactJwt, header, toClaimMap(claims), clock.get()));
  }

  private Optional<JwtValidationError> validateClaims(JWTClaimsSet claims) {
    Instant now = clock.get();
    long leeway = expectations.skewPolicy().leeway().getSeconds();

    Date exp = claims.getExpirationTime();
    if (exp == null) {
      if (expectations.requireExp()) {
        return Optional.of(new JwtValidationError.ClaimInvalid("claims/exp-missing", "exp is required"));
      }
    } else if (now.getEpochSecond() > exp.toInstant().getEpochSecond() + leeway) {
      return Optional.of(new JwtValidationError.Expired("token is expired"));
    }

    Date nbf = claims.getNotBeforeTime();
    if (nbf == null) {
      if (expectations.requireNbf()) {
        return Optional.of(new JwtValidationError.ClaimInvalid("claims/nbf-missing", "nbf is required"));
      }
    } else if (now.getEpochSecond() < nbf.toInstant().getEpochSecond() - leeway) {
      return Optional.of(new JwtValidationError.NotYetValid("token is not yet valid"));
    }

    if (expectations.requireIat() && claims.getIssueTime() == null) {
      return Optional.of(new JwtValidationError.ClaimInvalid("claims/iat-missing", "iat is required"));
    }
    if (expectations.requireJti() && claims.getJWTID() == null) {
      return Optional.of(new JwtValidationError.ClaimInvalid("claims/jti-missing", "jti is required"));
    }

    if (expectations.expectedIssuer().isPresent()
        && !expectations.expectedIssuer().get().equals(claims.getIssuer())) {
      return Optional.of(new JwtValidationError.ClaimInvalid(
          "claims/issuer-mismatch", "issuer does not match the expected value"));
    }

    if (!expectations.acceptedAudiences().isEmpty()) {
      List<String> aud = claims.getAudience();
      boolean ok = aud != null && aud.stream().anyMatch(expectations.acceptedAudiences()::contains);
      if (!ok) {
        return Optional.of(new JwtValidationError.ClaimInvalid(
            "claims/audience-mismatch", "no audience matches the accepted set"));
      }
    }
    return Optional.empty();
  }

  private static boolean familyMatches(JwsAlgorithm alg, PublicKey key) {
    return switch (alg) {
      case RS256, RS384, RS512, PS256, PS384, PS512 -> key instanceof RSAPublicKey;
      case ES256, ES384, ES512 -> key instanceof ECPublicKey;
      case EdDSA -> "EdDSA".equalsIgnoreCase(key.getAlgorithm())
          || "Ed25519".equalsIgnoreCase(key.getAlgorithm());
    };
  }

  private static Optional<JWSVerifier> verifierFor(JwsAlgorithm alg, PublicKey key) {
    try {
      return switch (alg) {
        case RS256, RS384, RS512, PS256, PS384, PS512 ->
            Optional.of(new RSASSAVerifier((RSAPublicKey) key));
        case ES256, ES384, ES512 ->
            Optional.of(new ECDSAVerifier((ECPublicKey) key));
        // EdDSA verifier (OctetKeyPair) wiring is completed in a follow-up.
        case EdDSA -> Optional.empty();
      };
    } catch (com.nimbusds.jose.JOSEException e) {
      return Optional.empty();
    }
  }

  private static int countSegments(String compact) {
    int dots = 0;
    for (int i = 0; i < compact.length(); i++) {
      if (compact.charAt(i) == '.') {
        dots++;
      }
    }
    return dots + 1;
  }

  private static Map<String, Object> toClaimMap(JWTClaimsSet claims) {
    Map<String, Object> out = new LinkedHashMap<>();
    for (Map.Entry<String, Object> e : claims.getClaims().entrySet()) {
      Object value = e.getValue();
      out.put(e.getKey(), value instanceof Date d ? d.toInstant() : value);
    }
    return out;
  }
}
