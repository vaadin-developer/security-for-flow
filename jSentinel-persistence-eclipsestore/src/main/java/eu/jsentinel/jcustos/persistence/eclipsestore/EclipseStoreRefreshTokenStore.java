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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link RefreshTokenStore}. */
final class EclipseStoreRefreshTokenStore implements RefreshTokenStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreRefreshTokenStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<RefreshTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().refreshTokens.get(tokenHash));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void save(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.lock().writeLock().lock();
    try {
      storage.root().refreshTokens.put(record.tokenHash(), record);
      storage.manager().store(storage.root().refreshTokens);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean markReplaced(String oldHash, String newHash, Instant at) {
    requireNonBlank(oldHash);
    if (newHash == null || newHash.isBlank()) {
      throw new IllegalArgumentException("newHash must not be blank");
    }
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      RefreshTokenRecord prev = storage.root().refreshTokens.get(oldHash);
      if (prev == null || prev.isReplaced()) {
        return false;
      }
      storage.root().refreshTokens.put(oldHash, prev.withReplacedBy(newHash));
      storage.manager().store(storage.root().refreshTokens);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean markRevoked(String tokenHash, Instant at) {
    requireNonBlank(tokenHash);
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      RefreshTokenRecord prev = storage.root().refreshTokens.get(tokenHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      storage.root().refreshTokens.put(tokenHash, prev.withRevokedAt(at));
      storage.manager().store(storage.root().refreshTokens);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    storage.lock().writeLock().lock();
    try {
      int before = storage.root().refreshTokens.size();
      storage.root().refreshTokens.values().removeIf(record ->
          record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
      int removed = before - storage.root().refreshTokens.size();
      if (removed > 0) {
        storage.manager().store(storage.root().refreshTokens);
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
      int before = storage.root().refreshTokens.size();
      storage.root().refreshTokens.values().removeIf(record -> record.isExpired(now));
      int removed = before - storage.root().refreshTokens.size();
      if (removed > 0) {
        storage.manager().store(storage.root().refreshTokens);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("oldHash must not be blank");
    }
  }
}
