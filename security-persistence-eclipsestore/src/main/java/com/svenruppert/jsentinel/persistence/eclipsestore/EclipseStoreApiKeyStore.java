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

import com.svenruppert.jsentinel.authentication.ApiKeyRecord;
import com.svenruppert.jsentinel.authentication.ApiKeyStore;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link ApiKeyStore}. */
final class EclipseStoreApiKeyStore implements ApiKeyStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreApiKeyStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<ApiKeyRecord> findByHash(String keyHash) {
    requireNonBlank(keyHash);
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().apiKeys.get(keyHash));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void save(ApiKeyRecord record) {
    requireNonNull(record, "record must not be null");
    storage.lock().writeLock().lock();
    try {
      storage.root().apiKeys.put(record.keyHash(), record);
      storage.manager().store(storage.root().apiKeys);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public List<ApiKeyRecord> listBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    storage.lock().readLock().lock();
    try {
      List<ApiKeyRecord> result = new ArrayList<>();
      for (ApiKeyRecord record : storage.root().apiKeys.values()) {
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
  public boolean markUsed(String keyHash, Instant at) {
    requireNonBlank(keyHash);
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      ApiKeyRecord prev = storage.root().apiKeys.get(keyHash);
      if (prev == null) {
        return false;
      }
      storage.root().apiKeys.put(keyHash, prev.withLastUsedAt(at));
      storage.manager().store(storage.root().apiKeys);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean revoke(String keyHash, Instant at) {
    requireNonBlank(keyHash);
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      ApiKeyRecord prev = storage.root().apiKeys.get(keyHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      storage.root().apiKeys.put(keyHash, prev.withRevokedAt(at));
      storage.manager().store(storage.root().apiKeys);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean deleteByHash(String keyHash) {
    requireNonBlank(keyHash);
    storage.lock().writeLock().lock();
    try {
      boolean removed = storage.root().apiKeys.remove(keyHash) != null;
      if (removed) {
        storage.manager().store(storage.root().apiKeys);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    storage.lock().writeLock().lock();
    try {
      int before = storage.root().apiKeys.size();
      storage.root().apiKeys.values().removeIf(record -> record.isExpired(now));
      int removed = before - storage.root().apiKeys.size();
      if (removed > 0) {
        storage.manager().store(storage.root().apiKeys);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("keyHash must not be blank");
    }
  }
}
