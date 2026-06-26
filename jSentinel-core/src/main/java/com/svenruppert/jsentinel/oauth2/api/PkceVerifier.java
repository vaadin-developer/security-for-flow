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
package com.svenruppert.jsentinel.oauth2.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * A PKCE code verifier (RFC 7636, V00.77) — the high-entropy secret kept between
 * the authorization request and the token-endpoint code exchange. jSentinel uses
 * {@code S256} only.
 *
 * <p>{@link #generate()} draws 32 bytes from {@link SecureRandom} and base64url-
 * encodes them (43 chars, ~256 bits). {@link #challenge()} is
 * {@code BASE64URL(SHA-256(ASCII(verifier)))}. The verifier value is masked in
 * {@link #toString()}.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public final class PkceVerifier {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final int MIN_LEN = 43;
  private static final int MAX_LEN = 128;

  private final String codeVerifier;

  private PkceVerifier(String codeVerifier) {
    this.codeVerifier = codeVerifier;
  }

  /** Generates a fresh verifier with 256 bits of entropy. */
  public static PkceVerifier generate() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return new PkceVerifier(B64URL.encodeToString(bytes));
  }

  /**
   * Wraps an existing verifier string (e.g. read back from a {@code StateStore}).
   *
   * @param codeVerifier 43–128 chars of the PKCE unreserved alphabet
   */
  public static PkceVerifier of(String codeVerifier) {
    Objects.requireNonNull(codeVerifier, "codeVerifier");
    int len = codeVerifier.length();
    if (len < MIN_LEN || len > MAX_LEN) {
      throw new IllegalArgumentException(
          "PKCE code_verifier must be " + MIN_LEN + "-" + MAX_LEN + " chars, was " + len);
    }
    return new PkceVerifier(codeVerifier);
  }

  /** @return the raw verifier value (to send as {@code code_verifier} on the token request). */
  public String value() {
    return codeVerifier;
  }

  /** @return the {@code S256} code challenge derived from this verifier. */
  public PkceChallenge challenge() {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] digest = sha256.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
      return new PkceChallenge(B64URL.encodeToString(digest), "S256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  @Override
  public String toString() {
    return "PkceVerifier[value=***]";
  }
}
