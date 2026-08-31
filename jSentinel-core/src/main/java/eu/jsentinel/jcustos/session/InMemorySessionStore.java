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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link SessionStore} backed by a
 * {@link LinkedHashMap} so {@link #findBySubject(TenantId, SubjectId)}
 * returns insertion-ordered results.
 * <p>
 * Thread-safety: a {@link ReentrantReadWriteLock} serialises writes
 * and lets queries proceed in parallel.
 */
@ExperimentalJCustosApi
public final class InMemorySessionStore implements SessionStore {

  private final Map<SessionId, SessionRecord> sessions = new LinkedHashMap<>();
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

  /** Creates an empty store. */
  public InMemorySessionStore() {
  }

  @Override
  public void save(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    lock.writeLock().lock();
    try {
      sessions.put(session.sessionId(), session);
    } finally {
      lock.writeLock().unlock();
    }
  }

  @Override
  public Optional<SessionRecord> findById(SessionId sessionId) {
    requireNonNull(sessionId, "sessionId must not be null");
    lock.readLock().lock();
    try {
      return Optional.ofNullable(sessions.get(sessionId));
    } finally {
      lock.readLock().unlock();
    }
  }

  @Override
  public List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    lock.readLock().lock();
    try {
      List<SessionRecord> result = new ArrayList<>();
      for (SessionRecord record : sessions.values()) {
        if (record.tenant().equals(tenant) && record.subjectId().equals(subjectId)) {
          result.add(record);
        }
      }
      return List.copyOf(result);
    } finally {
      lock.readLock().unlock();
    }
  }

  @Override
  public boolean delete(SessionId sessionId) {
    requireNonNull(sessionId, "sessionId must not be null");
    lock.writeLock().lock();
    try {
      return sessions.remove(sessionId) != null;
    } finally {
      lock.writeLock().unlock();
    }
  }

  @Override
  public List<SessionRecord> findAll() {
    lock.readLock().lock();
    try {
      return List.copyOf(sessions.values());
    } finally {
      lock.readLock().unlock();
    }
  }
}
