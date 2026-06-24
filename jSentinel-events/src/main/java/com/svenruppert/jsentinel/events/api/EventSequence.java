package com.svenruppert.jsentinel.events.api;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

/**
 * Monotone sequence number scoped to {@code tenantId + producerId}
 * (Konzept §339). Lets a consumer detect gaps, repeats and roll-backs.
 *
 * @param value non-negative monotone counter
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record EventSequence(long value) implements Comparable<EventSequence> {

  /** The first valid sequence in a fresh {@code (tenant, producer)} scope. */
  public static final EventSequence FIRST = new EventSequence(1L);

  public EventSequence {
    if (value < 0) {
      throw new IllegalArgumentException("EventSequence value must be >= 0, was " + value);
    }
  }

  public static EventSequence of(long value) {
    return new EventSequence(value);
  }

  /**
   * @return the immediately following sequence
   * @throws ArithmeticException if this sequence is already at
   *         {@link Long#MAX_VALUE} (R039 — guard the overflow that would
   *         otherwise wrap to a negative value and break the monotonicity the
   *         gap/repeat/roll-back detection relies on)
   */
  public EventSequence next() {
    if (value == Long.MAX_VALUE) {
      throw new ArithmeticException(
          "EventSequence overflow: cannot advance past Long.MAX_VALUE");
    }
    return new EventSequence(value + 1);
  }

  @Override
  public int compareTo(EventSequence other) {
    return Long.compare(value, other.value);
  }
}
