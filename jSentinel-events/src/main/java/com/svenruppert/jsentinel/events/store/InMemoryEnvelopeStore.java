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
import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory {@link JSentinelEventEnvelopeStore}. The append index <em>is</em>
 * the stable cursor position (1-based). All access is synchronized.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class InMemoryEnvelopeStore implements JSentinelEventEnvelopeStore {

  private final List<SignedJSentinelEventEnvelope> envelopes = new ArrayList<>();

  @Override
  public synchronized JSentinelEventCursor append(SignedJSentinelEventEnvelope envelope) {
    envelopes.add(Objects.requireNonNull(envelope, "envelope"));
    return JSentinelEventCursor.at(envelopes.size());
  }

  @Override
  public synchronized List<StoredEnvelope> findAfter(JSentinelEventCursor cursor, int limit) {
    Objects.requireNonNull(cursor, "cursor");
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0, was " + limit);
    }
    List<StoredEnvelope> page = new ArrayList<>();
    // positions are 1-based; index i holds position i+1
    for (long position = cursor.position() + 1; position <= envelopes.size(); position++) {
      if (page.size() >= limit) {
        break;
      }
      page.add(new StoredEnvelope(
          JSentinelEventCursor.at(position), envelopes.get((int) (position - 1))));
    }
    return page;
  }

  @Override
  public synchronized Optional<SignedJSentinelEventEnvelope> findByEnvelopeId(
      EventEnvelopeId envelopeId) {
    Objects.requireNonNull(envelopeId, "envelopeId");
    for (SignedJSentinelEventEnvelope envelope : envelopes) {
      if (envelope.envelopeId().equals(envelopeId)) {
        return Optional.of(envelope);
      }
    }
    return Optional.empty();
  }

  @Override
  public synchronized long count() {
    return envelopes.size();
  }
}
