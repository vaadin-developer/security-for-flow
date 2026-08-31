package eu.jsentinel.jcustos.events.store;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory {@link JCustosEventEnvelopeStore}. The append index <em>is</em>
 * the stable cursor position (1-based). All access is synchronized.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class InMemoryEnvelopeStore implements JCustosEventEnvelopeStore {

  private final List<SignedJCustosEventEnvelope> envelopes = new ArrayList<>();

  @Override
  public synchronized JCustosEventCursor append(SignedJCustosEventEnvelope envelope) {
    envelopes.add(Objects.requireNonNull(envelope, "envelope"));
    return JCustosEventCursor.at(envelopes.size());
  }

  @Override
  public synchronized List<StoredEnvelope> findAfter(JCustosEventCursor cursor, int limit) {
    Objects.requireNonNull(cursor, "cursor");
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0, was " + limit);
    }
    List<StoredEnvelope> page = new ArrayList<>();
    // JS-SEC-058 (CWE-190): return an empty page for an at/after-end cursor, which also makes the
    // `position + 1` overflow unreachable — a Long.MAX_VALUE cursor (only position >= 0 is validated)
    // would otherwise overflow to Long.MIN_VALUE, enter the loop, and throw from
    // JCustosEventCursor.at(Long.MIN_VALUE) instead of returning "nothing after it".
    long from = cursor.position();
    if (from >= envelopes.size()) {
      return page;
    }
    // positions are 1-based; index i holds position i+1
    for (long position = from + 1; position <= envelopes.size(); position++) {
      if (page.size() >= limit) {
        break;
      }
      page.add(new StoredEnvelope(
          JCustosEventCursor.at(position), envelopes.get((int) (position - 1))));
    }
    return page;
  }

  @Override
  public synchronized Optional<SignedJCustosEventEnvelope> findByEnvelopeId(
      EventEnvelopeId envelopeId) {
    Objects.requireNonNull(envelopeId, "envelopeId");
    for (SignedJCustosEventEnvelope envelope : envelopes) {
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
