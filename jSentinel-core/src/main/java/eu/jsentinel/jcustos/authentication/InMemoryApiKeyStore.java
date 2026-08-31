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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link ApiKeyStore} backed by a
 * {@link LinkedHashMap} so {@link #listBySubject(TenantId, SubjectId)}
 * preserves insertion order. Read-write lock keeps mutations atomic
 * while letting concurrent lookups proceed.
 */
@ExperimentalJSentinelApi
public final class InMemoryApiKeyStore implements ApiKeyStore {

  private final Map<String, ApiKeyRecord> keys = new LinkedHashMap<>();
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

  /** Creates an empty store. */
  public InMemoryApiKeyStore() {
  }

  @Override
  public Optional<ApiKeyRecord> findByHash(String keyHash) {
    requireNonBlank(keyHash);
    lock.readLock().lock();
    try {
      return Optional.ofNullable(keys.get(keyHash));
    } finally {
      lock.readLock().unlock();
    }
  }

  @Override
  public void save(ApiKeyRecord record) {
    requireNonNull(record, "record must not be null");
    lock.writeLock().lock();
    try {
      keys.put(record.keyHash(), record);
    } finally {
      lock.writeLock().unlock();
    }
  }

  @Override
  public List<ApiKeyRecord> listBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    lock.readLock().lock();
    try {
      List<ApiKeyRecord> result = new ArrayList<>();
      for (ApiKeyRecord record : keys.values()) {
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
  public boolean markUsed(String keyHash, Instant at) {
    requireNonBlank(keyHash);
    requireNonNull(at, "at must not be null");
    lock.writeLock().lock();
    try {
      ApiKeyRecord prev = keys.get(keyHash);
      if (prev == null) {
        return false;
      }
      keys.put(keyHash, prev.withLastUsedAt(at));
      return true;
    } finally {
      lock.writeLock().unlock();
    }
  }

  @Override
  public boolean revoke(String keyHash, Instant at) {
    requireNonBlank(keyHash);
    requireNonNull(at, "at must not be null");
    lock.writeLock().lock();
    try {
      ApiKeyRecord prev = keys.get(keyHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      keys.put(keyHash, prev.withRevokedAt(at));
      return true;
    } finally {
      lock.writeLock().unlock();
    }
  }

  @Override
  public boolean deleteByHash(String keyHash) {
    requireNonBlank(keyHash);
    lock.writeLock().lock();
    try {
      return keys.remove(keyHash) != null;
    } finally {
      lock.writeLock().unlock();
    }
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    lock.writeLock().lock();
    try {
      int before = keys.size();
      keys.values().removeIf(record -> record.isExpired(now));
      return before - keys.size();
    } finally {
      lock.writeLock().unlock();
    }
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("keyHash must not be blank");
    }
  }
}
