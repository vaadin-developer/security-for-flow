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
package com.svenruppert.jsentinel.oauth2;

/*-
 * #%L
 * jSentinel OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.credential.secret.SecretValue;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;
import com.svenruppert.jsentinel.oauth2.api.RefreshTokenFamilyStore;
import com.svenruppert.jsentinel.oauth2.api.TokenEndpointClient;
import com.svenruppert.jsentinel.oauth2.api.TokenResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * Refresh-token rotation with reuse-detection (BCP 9700 §4.13.2, V00.77). A
 * refresh is performed against the {@link TokenEndpointClient}; the presented
 * and newly-issued refresh tokens are tracked by hash in the
 * {@link RefreshTokenFamilyStore}. A replayed (already-rotated) refresh token is
 * detected <em>before</em> it is forwarded to the authorization server
 * ({@link RefreshTokenFamilyStore#detectReuse}); on that theft signal the whole
 * family is revoked and the rotation fails with
 * {@link OAuth2Error.RefreshTokenFamilyRevoked} — independent of whether the
 * authorization server itself rejects the replayed token.
 *
 * <p>Only token hashes leave this class; raw refresh-token values are never
 * stored or logged.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public final class RefreshTokenRotator {

  private final TokenEndpointClient endpoint;
  private final RefreshTokenFamilyStore familyStore;

  public RefreshTokenRotator(TokenEndpointClient endpoint, RefreshTokenFamilyStore familyStore) {
    this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
    this.familyStore = Objects.requireNonNull(familyStore, "familyStore");
  }

  /**
   * Refreshes the access token for {@code familyId} using {@code presentedRefreshToken}
   * and rotates the family.
   *
   * @param familyId              the token-family identifier (e.g. the subject id)
   * @param presentedRefreshToken the refresh token the client presented
   * @return the new tokens on success, or an {@link OAuth2Error} (including
   *         {@link OAuth2Error.RefreshTokenFamilyRevoked} on reuse-detection)
   */
  public Result<TokenResponse, OAuth2Error> rotate(String familyId, SecretValue presentedRefreshToken) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(presentedRefreshToken, "presentedRefreshToken");
    byte[] presentedBytes = presentedRefreshToken.asUtf8Bytes();
    String presentedHash;
    try {
      presentedHash = sha256Hex(presentedBytes);
    } finally {
      java.util.Arrays.fill(presentedBytes, (byte) 0);
    }

    // R-EXIT-1: detect a replayed (already-rotated) token BEFORE forwarding it to
    // the AS. A correctly-rotating AS rejects a replayed token, so gating the
    // family revoke on AS success would never fire on the theft path. Revoke now,
    // and never forward a replayed token onward.
    if (familyStore.detectReuse(familyId, presentedHash)
        == RefreshTokenFamilyStore.RotationResult.REUSE_DETECTED) {
      return Result.failure(new OAuth2Error.RefreshTokenFamilyRevoked());
    }

    Result<TokenResponse, OAuth2Error> result = endpoint.refresh(presentedRefreshToken);
    Optional<TokenResponse> success = result.toOptional();
    if (success.isEmpty()) {
      // a current token the AS rejected for a non-reuse reason (e.g. expired) —
      // do not revoke the family.
      return result;
    }

    TokenResponse tokens = success.get();
    String newHash = tokens.refreshToken()
        .map(rt -> sha256Hex(rt.getBytes(StandardCharsets.UTF_8)))
        .orElse(presentedHash);

    RefreshTokenFamilyStore.RotationResult rotation =
        familyStore.consumeAndRotate(familyId, presentedHash, newHash);
    if (rotation == RefreshTokenFamilyStore.RotationResult.REUSE_DETECTED) {
      return Result.failure(new OAuth2Error.RefreshTokenFamilyRevoked());
    }
    return Result.success(tokens);
  }

  /** Registers the initial refresh token of a freshly-issued family. */
  public void registerInitial(String familyId, String refreshTokenValue) {
    familyStore.recordIssued(familyId, sha256Hex(refreshTokenValue.getBytes(StandardCharsets.UTF_8)));
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
