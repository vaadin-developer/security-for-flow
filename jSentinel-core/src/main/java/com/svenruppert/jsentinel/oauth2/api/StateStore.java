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

import java.time.Duration;
import java.util.Optional;

/**
 * Storage for the short-lived authorization {@code state} → {@link StateEntry}
 * mapping (V00.77). The contract is <strong>single-use</strong>: a successful
 * {@link #consume(String)} removes the entry, so a replayed callback with the
 * same {@code state} cannot be processed twice. Adapters provide concrete
 * implementations (Vaadin session, JDK in-memory, thread-local).
 *
 * @since 00.77.00
 */
public interface StateStore {

  /**
   * Binds {@code entry} under {@code stateKey} with the given TTL.
   *
   * @param stateKey the high-entropy {@code state} value
   * @param entry    the per-request state
   * @param ttl      how long the entry stays consumable
   */
  void bind(String stateKey, StateEntry entry, Duration ttl);

  /**
   * Atomically removes and returns the entry for {@code stateKey}, or empty if it
   * is unknown, already consumed, or expired. Single-use by contract.
   *
   * @param stateKey the {@code state} value from the callback
   * @return the bound entry, or empty
   */
  Optional<StateEntry> consume(String stateKey);

  /** Drops all entries (e.g. on logout / session invalidation). */
  void clear();
}
