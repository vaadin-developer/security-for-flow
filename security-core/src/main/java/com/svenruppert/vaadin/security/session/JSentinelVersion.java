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
package com.svenruppert.vaadin.security.session;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;

/**
 * Monotonically-increasing version of a subject's security-relevant
 * state (roles, permissions, password, …).
 * <p>
 * Stored on a {@code SessionRecord} as
 * {@code securityVersionAtLogin}; a downstream
 * {@code JSentinelVersionCheck} (planned for V00.70 Phase 4) compares
 * the value at request time against the subject's <em>current</em>
 * security version, and refuses the session once they drift apart.
 *
 * <p>The version is intentionally a {@code long} (not an
 * {@code Instant}): it expresses ordering, not real time, and is
 * cheap to increment from any application code path that mutates a
 * subject's authority.
 *
 * <p>{@link #INITIAL} is the canonical starting point for any new
 * subject; comparisons (less-than / greater-than) work directly on the
 * {@code value} component.
 *
 * @param value non-negative version counter
 */
@ExperimentalJSentinelApi
public record JSentinelVersion(long value) implements Comparable<JSentinelVersion> {

  /**
   * Initial version (zero) — the value used when a subject is first
   * persisted.
   */
  public static final JSentinelVersion INITIAL = new JSentinelVersion(0L);

  /**
   * Validates the record component.
   *
   * @param value non-negative version counter
   */
  public JSentinelVersion {
    if (value < 0) {
      throw new IllegalArgumentException("value must not be negative");
    }
  }

  /**
   * Returns the next-higher version. Pure function — the receiver is
   * unchanged.
   *
   * @return version with {@code value + 1}
   */
  public JSentinelVersion next() {
    return new JSentinelVersion(value + 1);
  }

  @Override
  public int compareTo(JSentinelVersion other) {
    return Long.compare(this.value, other.value);
  }
}
