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
package com.svenruppert.jsentinel.identity.oidc;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
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

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;
import com.svenruppert.jsentinel.oidc.api.IdTokenExpectations;
import com.svenruppert.jsentinel.oidc.api.IdTokenValidationError;
import com.svenruppert.jsentinel.oidc.api.IdTokenValidator;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The default OIDC {@link IdTokenValidator} (V00.78). Per the A.0 review-gate it
 * <em>composes</em> a V00.76 {@link JwtValidator} (the Nimbus impl is {@code final})
 * rather than subtyping it: the JWT-standard validation (signature / exp / iss /
 * aud) runs first, then the OIDC Core §3.1.3.7 checks layer on top —
 * {@code nonce}, {@code azp}, {@code at_hash} / {@code c_hash} (§3.1.3.6),
 * {@code auth_time} vs {@code max_age}, and {@code acr}. No JOSE library is
 * imported here; the hash checks use the JDK {@link MessageDigest}.
 */
public final class DefaultIdTokenValidator implements IdTokenValidator {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private final JwtValidator jwtValidator;
  private final Supplier<Instant> clock;

  public DefaultIdTokenValidator(JwtValidator jwtValidator) {
    this(jwtValidator, Instant::now);
  }

  public DefaultIdTokenValidator(JwtValidator jwtValidator, Supplier<Instant> clock) {
    this.jwtValidator = Objects.requireNonNull(jwtValidator, "jwtValidator");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Result<ValidatedIdToken, IdTokenValidationError> validate(
      String compactIdToken, IdTokenExpectations expectations) {
    Objects.requireNonNull(compactIdToken, "compactIdToken");
    Objects.requireNonNull(expectations, "expectations");

    // 1. JWT-standard validation (signature, exp, iss, aud) via the composed SPI.
    Result<ValidatedJwt, JwtValidationError> jwtResult = jwtValidator.validate(compactIdToken);
    Optional<ValidatedJwt> ok = jwtResult.toOptional();
    if (ok.isEmpty()) {
      return Result.failure(new IdTokenValidationError.JwtInvalid(
          jwtResult.fold(v -> null, e -> e)));
    }
    ValidatedJwt jwt = ok.get();

    List<String> audiences = jwt.audience().orElse(List.of());
    Optional<String> azp = jwt.claim("azp", String.class);

    // 2. nonce — must equal the value bound at authorization time.
    if (expectations.expectedNonce().isPresent()) {
      Optional<String> nonce = jwt.claim("nonce", String.class);
      if (!expectations.expectedNonce().equals(nonce)) {
        return Result.failure(new IdTokenValidationError.NonceMismatch());
      }
    }

    // 3. azp — required when aud has multiple entries or azp is present; must match the client.
    if (audiences.size() > 1 || azp.isPresent()) {
      if (!azp.equals(Optional.of(expectations.expectedAudience()))) {
        return Result.failure(new IdTokenValidationError.AuthorizedPartyInvalid());
      }
    }

    // 4. at_hash — OIDC Core §3.1.3.6.
    if (expectations.accessTokenForAtHash().isPresent()) {
      Optional<String> atHash = jwt.claim("at_hash", String.class);
      String expected = leftHalfHash(expectations.accessTokenForAtHash().get(), jwt.header().alg());
      if (expected == null || atHash.isEmpty() || !constantTimeEquals(expected, atHash.get())) {
        return Result.failure(new IdTokenValidationError.AccessTokenHashMismatch());
      }
    }

    // 5. c_hash — same construction over the authorization code (hybrid flow; SPI-ready).
    if (expectations.codeForCHash().isPresent()) {
      Optional<String> cHash = jwt.claim("c_hash", String.class);
      String expected = leftHalfHash(expectations.codeForCHash().get(), jwt.header().alg());
      if (expected == null || cHash.isEmpty() || !constantTimeEquals(expected, cHash.get())) {
        return Result.failure(new IdTokenValidationError.CodeHashMismatch());
      }
    }

    // 6. auth_time vs max_age — re-authentication freshness.
    Optional<Instant> authTime = epochSecondClaim(jwt, "auth_time");
    if (expectations.maxAge().isPresent()) {
      Duration maxAge = expectations.maxAge().get();
      Instant deadline = clock.get().minus(maxAge).minus(expectations.clockSkew());
      if (authTime.isEmpty() || authTime.get().isBefore(deadline)) {
        return Result.failure(new IdTokenValidationError.AuthTimeStale());
      }
    }

    // 7. acr — must be one of the requested authentication-context classes.
    Optional<String> acr = jwt.claim("acr", String.class);
    if (!expectations.requestedAcr().isEmpty()
        && (acr.isEmpty() || !expectations.requestedAcr().contains(acr.get()))) {
      return Result.failure(new IdTokenValidationError.AcrUnsatisfied());
    }

    return Result.success(new ValidatedIdToken(
        jwt,
        jwt.claim("nonce", String.class),
        authTime,
        acr,
        amr(jwt),
        azp,
        jwt.claim("session_state", String.class)));
  }

  /** OIDC §3.1.3.6: base64url(left-most half of HASH(ascii(value))), hash chosen by the JWS alg. */
  private static String leftHalfHash(String value, String alg) {
    String digestName = switch (alg) {
      case "RS256", "ES256", "PS256", "HS256" -> "SHA-256";
      case "RS384", "ES384", "PS384", "HS384" -> "SHA-384";
      case "RS512", "ES512", "PS512", "HS512", "EdDSA" -> "SHA-512";
      default -> null;
    };
    if (digestName == null) {
      return null;
    }
    try {
      byte[] digest = MessageDigest.getInstance(digestName)
          .digest(value.getBytes(StandardCharsets.US_ASCII));
      return B64URL.encodeToString(Arrays.copyOfRange(digest, 0, digest.length / 2));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(digestName + " unavailable", e);
    }
  }

  private static Optional<Instant> epochSecondClaim(ValidatedJwt jwt, String name) {
    Object value = jwt.claims().get(name);
    if (value instanceof Number n) {
      return Optional.of(Instant.ofEpochSecond(n.longValue()));
    }
    return Optional.empty();
  }

  private static List<String> amr(ValidatedJwt jwt) {
    Object value = jwt.claims().get("amr");
    if (value instanceof List<?> list) {
      List<String> out = new ArrayList<>(list.size());
      for (Object o : list) {
        if (o instanceof String s) {
          out.add(s);
        }
      }
      return List.copyOf(out);
    }
    return List.of();
  }

  private static boolean constantTimeEquals(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.US_ASCII), b.getBytes(StandardCharsets.US_ASCII));
  }
}
