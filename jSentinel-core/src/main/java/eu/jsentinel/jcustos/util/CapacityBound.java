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
package eu.jsentinel.jcustos.util;

/**
 * Single home for the capacity-bound contract shared by every in-memory store keyed on
 * attacker-controlled input (CWE-770).
 *
 * <p>Several reference stores independently cap their maps to defend against a spray of distinct
 * keys — {@code InMemoryAbuseDetectionService}, {@code InMemoryJtiStore},
 * {@code JdkInMemoryStateStore}, {@code InMemoryReplayStore}. The bound value {@code 100_000} and
 * the {@code <1} guard were copy-pasted under two different constant names, and the
 * {@code *-store-capacity-exceeded} diagnostic code existed in one place. This class holds the one
 * shared <em>constant + guard + code</em>. It deliberately does <strong>not</strong> impose a single
 * eviction algorithm: bounded stores fall into two behaviour families (evict-oldest vs.
 * throw-on-full), and each keeps its own strategy.
 *
 * @since 00.79.41
 */
public final class CapacityBound {

  /** Default upper bound on the number of tracked keys for an attacker-keyed in-memory store. */
  public static final int DEFAULT_MAX_ENTRIES = 100_000;

  private CapacityBound() {
  }

  /**
   * Validates a configured capacity.
   *
   * @param capacity the requested capacity
   * @return {@code capacity} when it is positive
   * @throws IllegalArgumentException if {@code capacity < 1}
   */
  public static int requirePositiveCapacity(int capacity) {
    if (capacity < 1) {
      throw new IllegalArgumentException("capacity must be >= 1, was " + capacity);
    }
    return capacity;
  }

  /**
   * Builds the stable diagnostic code a bounded store throws when it is full of live entries.
   *
   * @param namespace the store's namespace (e.g. {@code "replay/nonce-store"})
   * @return {@code "<namespace>-capacity-exceeded"}
   */
  public static String capacityExceededCode(String namespace) {
    return namespace + "-capacity-exceeded";
  }
}
