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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.oauth2.api.RefreshTokenFamilyStore;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * In-process {@link RefreshTokenFamilyStore} (V00.77). Holds only the current
 * refresh-token <em>hash</em> per family. {@link #consumeAndRotate} is atomic
 * under {@code synchronized}: presenting the current hash rotates the family to
 * the new hash; presenting anything else (an already-rotated token being
 * replayed, or a revoked family) revokes the family and reports
 * {@link RotationResult#REUSE_DETECTED}.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public final class InMemoryRefreshTokenFamilyStore implements RefreshTokenFamilyStore {

  private final Map<String, String> currentHashByFamily = new HashMap<>();
  private final Set<String> revokedFamilies = new HashSet<>();

  @Override
  public synchronized void recordIssued(String familyId, String tokenHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(tokenHash, "tokenHash");
    revokedFamilies.remove(familyId);
    currentHashByFamily.put(familyId, tokenHash);
  }

  @Override
  public synchronized RotationResult consumeAndRotate(String familyId, String presentedHash, String newHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(presentedHash, "presentedHash");
    Objects.requireNonNull(newHash, "newHash");
    if (revokedFamilies.contains(familyId)) {
      return RotationResult.REUSE_DETECTED;
    }
    String current = currentHashByFamily.get(familyId);
    if (current != null && current.equals(presentedHash)) {
      currentHashByFamily.put(familyId, newHash);
      return RotationResult.ROTATED;
    }
    // an already-rotated or unknown token was replayed — theft signal (BCP 9700)
    revokeFamily(familyId);
    return RotationResult.REUSE_DETECTED;
  }

  @Override
  public synchronized RotationResult detectReuse(String familyId, String presentedHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(presentedHash, "presentedHash");
    if (revokedFamilies.contains(familyId)) {
      return RotationResult.REUSE_DETECTED;
    }
    String current = currentHashByFamily.get(familyId);
    if (current != null && current.equals(presentedHash)) {
      return RotationResult.ROTATED; // current — safe to forward, no rotation yet
    }
    // an already-rotated or unknown token was replayed — revoke before the AS call
    revokeFamily(familyId);
    return RotationResult.REUSE_DETECTED;
  }

  @Override
  public synchronized void revokeFamily(String familyId) {
    Objects.requireNonNull(familyId, "familyId");
    currentHashByFamily.remove(familyId);
    revokedFamilies.add(familyId);
  }

  /** @return whether {@code familyId} has been revoked (test/diagnostic aid). */
  public synchronized boolean isRevoked(String familyId) {
    return revokedFamilies.contains(familyId);
  }
}
