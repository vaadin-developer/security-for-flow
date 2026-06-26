package com.svenruppert.jsentinel.events.store;

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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * In-memory {@link JSentinelEventDeadLetterStore}. Insertion order is
 * preserved so {@link #findOpen(int)} returns oldest-first. All access is
 * synchronized.
 *
 * <p>R07 (V00.76.10): {@link #markResolved(DeadLetterId)} now removes the record
 * entirely rather than parking its id in a side set while keeping the heavy
 * record (each embeds a full signed envelope). The store therefore only retains
 * <em>open</em> dead letters and cannot grow without bound for a producer that
 * reliably trips a rejection reason.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class InMemoryDeadLetterStore implements JSentinelEventDeadLetterStore {

  private final Map<DeadLetterId, JSentinelEventDeadLetter> records = new LinkedHashMap<>();

  @Override
  public synchronized void store(JSentinelEventDeadLetter deadLetter) {
    Objects.requireNonNull(deadLetter, "deadLetter");
    records.put(deadLetter.id(), deadLetter);
  }

  @Override
  public synchronized List<JSentinelEventDeadLetter> findOpen(int limit) {
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0, was " + limit);
    }
    List<JSentinelEventDeadLetter> open = new ArrayList<>();
    for (JSentinelEventDeadLetter record : records.values()) {
      if (open.size() >= limit) {
        break;
      }
      open.add(record);
    }
    return open;
  }

  @Override
  public synchronized void markResolved(DeadLetterId id) {
    // R07: drop the record (and its embedded signed envelope) — a resolved dead
    // letter no longer needs retention, so resolved records cannot accumulate.
    records.remove(Objects.requireNonNull(id, "id"));
  }

  /** Test seam (R07): the number of retained (open) dead-letter records. */
  synchronized int retainedRecordCount() {
    return records.size();
  }
}
