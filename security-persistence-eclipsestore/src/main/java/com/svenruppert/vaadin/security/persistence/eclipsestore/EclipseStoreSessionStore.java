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
package com.svenruppert.vaadin.security.persistence.eclipsestore;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.SessionId;
import com.svenruppert.vaadin.security.session.SessionRecord;
import com.svenruppert.vaadin.security.session.SessionStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link SessionStore}. */
final class EclipseStoreSessionStore implements SessionStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreSessionStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public void save(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    storage.lock().writeLock().lock();
    try {
      storage.root().sessions.put(session.sessionId(), session);
      storage.manager().store(storage.root().sessions);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public Optional<SessionRecord> findById(SessionId sessionId) {
    requireNonNull(sessionId, "sessionId must not be null");
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().sessions.get(sessionId));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    storage.lock().readLock().lock();
    try {
      List<SessionRecord> result = new ArrayList<>();
      for (SessionRecord record : storage.root().sessions.values()) {
        if (record.tenant().equals(tenant) && record.subjectId().equals(subjectId)) {
          result.add(record);
        }
      }
      return List.copyOf(result);
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public boolean delete(SessionId sessionId) {
    requireNonNull(sessionId, "sessionId must not be null");
    storage.lock().writeLock().lock();
    try {
      boolean removed = storage.root().sessions.remove(sessionId) != null;
      if (removed) {
        storage.manager().store(storage.root().sessions);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public List<SessionRecord> findAll() {
    storage.lock().readLock().lock();
    try {
      return List.copyOf(storage.root().sessions.values());
    } finally {
      storage.lock().readLock().unlock();
    }
  }
}
