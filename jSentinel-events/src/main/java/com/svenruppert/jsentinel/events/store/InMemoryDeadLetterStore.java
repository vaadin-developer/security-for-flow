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
import java.util.Set;

/**
 * In-memory {@link JSentinelEventDeadLetterStore}. Insertion order is
 * preserved so {@link #findOpen(int)} returns oldest-first. All access is
 * synchronized.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class InMemoryDeadLetterStore implements JSentinelEventDeadLetterStore {

  private final Map<DeadLetterId, JSentinelEventDeadLetter> records = new LinkedHashMap<>();
  private final Set<DeadLetterId> resolved = new java.util.HashSet<>();

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
      if (!resolved.contains(record.id())) {
        open.add(record);
      }
    }
    return open;
  }

  @Override
  public synchronized void markResolved(DeadLetterId id) {
    resolved.add(Objects.requireNonNull(id, "id"));
  }
}
