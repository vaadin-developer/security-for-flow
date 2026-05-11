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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;

/**
 * Bounded in-memory ring buffer of {@link AuditEvent}s. New events are
 * appended at the tail; when the configured {@link #capacity()} is reached
 * the oldest event is dropped.
 * <p>
 * Intended to back the Vaadin {@code /audit}-route with a recent-events
 * view without paying for a persistent backend. Production deployments
 * typically combine this with a long-term sink (file, SIEM) inside a
 * {@code CompositeAuditService}.
 * <p>
 * Thread-safe via intrinsic locking on the internal buffer.
 */
public final class RingBufferAuditSink implements AuditSink {

  /** Default capacity if no explicit size is configured. */
  public static final int DEFAULT_CAPACITY = 256;

  private final int capacity;
  private final Deque<AuditEvent> buffer;

  /** Builds a ring buffer with {@link #DEFAULT_CAPACITY} slots. */
  public RingBufferAuditSink() {
    this(DEFAULT_CAPACITY);
  }

  /**
   * @param capacity maximum retained events; must be ≥ 1
   */
  public RingBufferAuditSink(int capacity) {
    if (capacity < 1) {
      throw new IllegalArgumentException("capacity must be >= 1");
    }
    this.capacity = capacity;
    this.buffer = new ArrayDeque<>(capacity);
  }

  /** Returns the configured maximum number of retained events. */
  public int capacity() {
    return capacity;
  }

  /** Returns the current number of retained events. */
  public int size() {
    synchronized (buffer) {
      return buffer.size();
    }
  }

  @Override
  public void accept(AuditEvent event) {
    Objects.requireNonNull(event, "event");
    synchronized (buffer) {
      if (buffer.size() == capacity) {
        buffer.removeFirst();
      }
      buffer.addLast(event);
    }
  }

  /**
   * Returns a snapshot of retained events that match {@code query},
   * oldest first.
   *
   * @param query filter, never {@code null}
   * @return defensive copy of matching events
   */
  public List<AuditEvent> query(AuditQuery query) {
    Objects.requireNonNull(query, "query");
    List<AuditEvent> snapshot;
    synchronized (buffer) {
      snapshot = new ArrayList<>(buffer);
    }
    List<AuditEvent> result = new ArrayList<>();
    int limit = query.limit();
    for (AuditEvent event : snapshot) {
      if (!query.matches(event)) {
        continue;
      }
      result.add(event);
      if (limit > 0 && result.size() >= limit) {
        break;
      }
    }
    return result;
  }

  /** Drops every retained event. */
  public void clear() {
    synchronized (buffer) {
      buffer.clear();
    }
  }
}
