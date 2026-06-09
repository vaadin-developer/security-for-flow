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
package com.svenruppert.jsentinel.persistence.eclipsestore;

import com.svenruppert.jsentinel.audit.AuditEnvelope;
import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditEventStore;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link AuditEventStore}. Operates on the
 * shared {@link EclipseStoreJSentinelRoot#auditEnvelopes} map under
 * the storage's read-write lock.
 */
final class EclipseStoreAuditEventStore implements AuditEventStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreAuditEventStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public AuditEnvelope append(TenantId tenant, AuditEvent event) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(event, "event must not be null");
    AuditEnvelope envelope = new AuditEnvelope(UUID.randomUUID().toString(), tenant, event);
    storage.lock().writeLock().lock();
    try {
      storage.root().auditEnvelopes.put(envelope.id(), envelope);
      storage.manager().store(storage.root().auditEnvelopes);
    } finally {
      storage.lock().writeLock().unlock();
    }
    return envelope;
  }

  @Override
  public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(query, "query must not be null");
    storage.lock().readLock().lock();
    try {
      List<AuditEnvelope> result = new ArrayList<>();
      for (AuditEnvelope envelope : storage.root().auditEnvelopes.values()) {
        if (envelope.tenant().equals(tenant) && query.matches(envelope.event())) {
          result.add(envelope);
        }
      }
      return List.copyOf(result);
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    storage.lock().writeLock().lock();
    try {
      int before = storage.root().auditEnvelopes.size();
      storage.root().auditEnvelopes.values()
          .removeIf(envelope -> envelope.event().timestamp().isBefore(cutoff));
      storage.manager().store(storage.root().auditEnvelopes);
      return before - storage.root().auditEnvelopes.size();
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
