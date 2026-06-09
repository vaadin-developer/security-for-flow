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
package com.svenruppert.jsentinel.ratelimiting;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * Result of a {@link RateLimitPolicy#tryAcquire} call.
 * <p>
 * Sealed because adapters dispatch on the two outcomes — let the
 * request through or refuse it with a {@code 429 Too Many
 * Requests} (REST) / equivalent rejection (UI).
 */
@ExperimentalJSentinelApi
public sealed interface RateLimitDecision {

  /**
   * @return the per-window event count after this decision (used /
   *         observed)
   */
  int eventsInWindow();

  /**
   * @return the configured per-window limit
   */
  int limit();

  /**
   * @return the configured window duration
   */
  Duration window();

  /** The event was admitted; the caller proceeds. */
  record Allowed(int eventsInWindow, int limit, Duration window) implements RateLimitDecision {
    /** Validates the components. */
    public Allowed {
      if (eventsInWindow < 0) {
        throw new IllegalArgumentException("eventsInWindow must not be negative");
      }
      if (limit <= 0) {
        throw new IllegalArgumentException("limit must be strictly positive");
      }
      requireNonNull(window, "window must not be null");
    }
  }

  /**
   * The event was refused — the per-window count is already at or
   * above the configured limit.
   *
   * @param eventsInWindow observed count
   * @param limit          configured limit
   * @param window         configured window
   * @param retryAfter     duration until the oldest in-window event
   *                       falls out of the window — a fair lower
   *                       bound for {@code Retry-After}; non-null,
   *                       non-negative
   */
  record Throttled(int eventsInWindow, int limit, Duration window, Duration retryAfter)
      implements RateLimitDecision {
    /** Validates the components. */
    public Throttled {
      if (eventsInWindow < 0) {
        throw new IllegalArgumentException("eventsInWindow must not be negative");
      }
      if (limit <= 0) {
        throw new IllegalArgumentException("limit must be strictly positive");
      }
      requireNonNull(window, "window must not be null");
      requireNonNull(retryAfter, "retryAfter must not be null");
      if (retryAfter.isNegative()) {
        throw new IllegalArgumentException("retryAfter must not be negative");
      }
    }
  }
}
