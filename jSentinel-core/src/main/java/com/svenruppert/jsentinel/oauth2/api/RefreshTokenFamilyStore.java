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

/**
 * Tracks refresh-token families for rotation + reuse-detection (BCP 9700
 * §4.13.2, V00.77). On each successful refresh the rotator presents the old
 * token's hash and the new token's hash; if the presented hash is not the
 * family's current one (i.e. an already-rotated token is being replayed — a
 * sign of theft), the whole family is revoked.
 *
 * <p>Only token <em>hashes</em> are stored, never raw token values.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public interface RefreshTokenFamilyStore {

  /** Records a freshly-issued family with its first refresh-token hash. */
  void recordIssued(String familyId, String tokenHash);

  /**
   * Atomically rotates the family: if {@code presentedHash} is the current hash,
   * replaces it with {@code newHash} and returns {@link RotationResult#ROTATED};
   * otherwise revokes the family and returns {@link RotationResult#REUSE_DETECTED}.
   *
   * @param familyId      the token-family identifier
   * @param presentedHash the hash of the refresh token presented by the client
   * @param newHash       the hash of the newly-issued refresh token
   * @return the rotation outcome
   */
  RotationResult consumeAndRotate(String familyId, String presentedHash, String newHash);

  /** Revokes a whole family (e.g. on logout, or after reuse-detection). */
  void revokeFamily(String familyId);

  /** The outcome of {@link #consumeAndRotate}. */
  enum RotationResult {
    /** The presented token was current; the family rotated to the new token. */
    ROTATED,
    /** An already-rotated (or unknown) token was replayed; the family was revoked. */
    REUSE_DETECTED
  }
}
