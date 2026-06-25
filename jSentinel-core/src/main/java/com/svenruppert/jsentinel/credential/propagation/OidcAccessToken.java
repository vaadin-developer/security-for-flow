/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.credential.propagation;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * OIDC access token. Semantically a bearer token plus a known issuer.
 * {@link #issuerHash()} is the SHA-256 hex of the issuer URL, retained
 * for audit metadata only.
 *
 * <p>V00.76 adds the optional {@link #validated()} component — present once a
 * {@code JwtValidator} has validated the token, so the inbound validation result
 * can be propagated through the V00.74 outbound path. The four pre-existing
 * components are unchanged; {@link #fromValidated(String, ValidatedJwt)} derives
 * them from a {@link ValidatedJwt}.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record OidcAccessToken(
    String value,
    Optional<Instant> expiresAt,
    Optional<String> audience,
    Optional<String> issuerHash,
    Optional<ValidatedJwt> validated)
    implements TokenCredential {

  public OidcAccessToken {
    Objects.requireNonNull(value, "value");
    if (value.isEmpty()) {
      throw new IllegalArgumentException("OidcAccessToken value must be non-empty");
    }
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(issuerHash, "issuerHash");
    Objects.requireNonNull(validated, "validated");
  }

  /**
   * Builds an {@code OidcAccessToken} from a validated JWT, deriving the audit
   * metadata (expiry, audience, issuer hash) from the validated claims and
   * carrying the {@link ValidatedJwt} in {@link #validated()}.
   *
   * @param raw       the raw compact token
   * @param validated the validation result
   * @return the token
   */
  public static OidcAccessToken fromValidated(String raw, ValidatedJwt validated) {
    Objects.requireNonNull(validated, "validated");
    return new OidcAccessToken(
        raw,
        validated.expiresAt(),
        validated.audience().map(a -> String.join(",", a)),
        validated.issuer().map(OidcAccessToken::sha256Hex),
        Optional.of(validated));
  }

  private static String sha256Hex(String input) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(input.getBytes(StandardCharsets.UTF_8));
      StringBuilder hex = new StringBuilder(digest.length * 2);
      for (byte b : digest) {
        hex.append(Character.forDigit((b >> 4) & 0xF, 16));
        hex.append(Character.forDigit(b & 0xF, 16));
      }
      return hex.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required but unavailable", e);
    }
  }

  @Override
  public String toString() {
    return "OidcAccessToken{exp=" + expiresAt.orElse(null)
        + ", aud=" + audience.orElse(null)
        + ", iss=" + issuerHash.orElse(null)
        + ", value=***}";
  }
}
