package eu.jsentinel.jcustos.events.persistence.eclipsestore;

/*-
 * #%L
 * jCustos Events — Eclipse-Store persistence
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

import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.store.JCustosEventCursor;
import eu.jsentinel.jcustos.events.store.JCustosEventEnvelopeStore;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Eclipse-Store-backed {@link JCustosEventEnvelopeStore} for resume +
 * diagnostics. The append index is the stable cursor position (Konzept §730).
 */
final class EclipseStoreEnvelopeStore implements JCustosEventEnvelopeStore {

  private final EclipseStoreEventStorage storage;

  EclipseStoreEnvelopeStore(EclipseStoreEventStorage storage) {
    this.storage = storage;
  }

  @Override
  public JCustosEventCursor append(SignedJCustosEventEnvelope envelope) {
    Objects.requireNonNull(envelope, "envelope");
    storage.lock().writeLock().lock();
    try {
      List<SignedJCustosEventEnvelope> envelopes = storage.root().envelopes;
      envelopes.add(envelope);
      storage.manager().store(envelopes);
      return JCustosEventCursor.at(envelopes.size());
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public List<StoredEnvelope> findAfter(JCustosEventCursor cursor, int limit) {
    Objects.requireNonNull(cursor, "cursor");
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0, was " + limit);
    }
    storage.lock().readLock().lock();
    try {
      List<SignedJCustosEventEnvelope> envelopes = storage.root().envelopes;
      List<StoredEnvelope> page = new ArrayList<>();
      // JS-SEC-058 (CWE-190): an at/after-end cursor returns an empty page, making the `position + 1`
      // overflow (Long.MAX_VALUE -> Long.MIN_VALUE, which would throw from JCustosEventCursor.at)
      // unreachable.
      long from = cursor.position();
      if (from >= envelopes.size()) {
        return page;
      }
      for (long position = from + 1;
           position <= envelopes.size() && page.size() < limit; position++) {
        page.add(new StoredEnvelope(
            JCustosEventCursor.at(position), envelopes.get((int) (position - 1))));
      }
      return page;
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public Optional<SignedJCustosEventEnvelope> findByEnvelopeId(EventEnvelopeId envelopeId) {
    Objects.requireNonNull(envelopeId, "envelopeId");
    storage.lock().readLock().lock();
    try {
      for (SignedJCustosEventEnvelope envelope : storage.root().envelopes) {
        if (envelope.envelopeId().equals(envelopeId)) {
          return Optional.of(envelope);
        }
      }
      return Optional.empty();
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public long count() {
    storage.lock().readLock().lock();
    try {
      return storage.root().envelopes.size();
    } finally {
      storage.lock().readLock().unlock();
    }
  }
}
