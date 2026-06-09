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
package com.svenruppert.vaadin.security.audit;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * {@link JSentinelAuditService} that fans every published event out to:
 * <ul>
 *   <li>a primary {@link RingBufferAuditSink} used as the query backend, and</li>
 *   <li>zero or more additional {@link AuditSink}s (logging, file, SIEM, …).</li>
 * </ul>
 * Every sink runs independently — a failing extra sink does not stop the
 * fan-out and never causes {@code publish(...)} to throw.
 * <p>
 * Queries always read from the ring buffer. Applications that need a
 * different query backend can wrap this class.
 */
public final class CompositeAuditService implements JSentinelAuditService {

  private final RingBufferAuditSink ringBuffer;
  private final List<AuditSink> extraSinks;

  /**
   * @param ringBuffer  query-backing in-memory buffer, never {@code null}
   * @param extraSinks  additional write-only sinks; may be empty
   */
  public CompositeAuditService(RingBufferAuditSink ringBuffer, AuditSink... extraSinks) {
    this.ringBuffer = Objects.requireNonNull(ringBuffer, "ringBuffer");
    this.extraSinks = extraSinks == null ? List.of() : List.copyOf(Arrays.asList(extraSinks));
  }

  @Override
  public void publish(AuditEvent event) {
    if (event == null) return;
    safeAccept(ringBuffer, event);
    for (AuditSink sink : extraSinks) {
      safeAccept(sink, event);
    }
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    Objects.requireNonNull(query, "query");
    return ringBuffer.query(query);
  }

  /** Visible for application setup code that wants to consult the buffer directly. */
  public RingBufferAuditSink ringBuffer() {
    return ringBuffer;
  }

  /** Returns an unmodifiable snapshot of the configured extra sinks. */
  public List<AuditSink> extraSinks() {
    return new ArrayList<>(extraSinks);
  }

  private static void safeAccept(AuditSink sink, AuditEvent event) {
    try {
      sink.accept(event);
    } catch (RuntimeException ignored) {
      // never propagate — audit failure must not interrupt the security flow
    }
  }
}
