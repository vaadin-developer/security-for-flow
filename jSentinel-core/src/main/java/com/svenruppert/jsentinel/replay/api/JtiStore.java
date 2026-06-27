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
package com.svenruppert.jsentinel.replay.api;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Instant;

/**
 * A single-use {@code jti} (JWT id) store for replay protection (V00.79) — the
 * backing for DPoP-proof single-use (RFC 9449 §11.1) and any other one-time-token
 * check. {@link #record(String, Instant)} atomically records a {@code jti} that has
 * not been seen; a second record of the same {@code jti} within its validity window
 * fails with {@link ReplayError}. Default impl is in-memory; production consumers
 * plug a shared store (JDBC / Redis). Implementations MUST be thread-safe.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public interface JtiStore {

  /**
   * Atomically records {@code jti} as seen until {@code expiresAt}.
   *
   * @param jti       the one-time identifier
   * @param expiresAt when this {@code jti} may be evicted (its proof's iat + skew)
   * @return success if newly recorded, or {@link ReplayError} if already seen
   */
  Result<Boolean, ReplayError> record(String jti, Instant expiresAt);
}
