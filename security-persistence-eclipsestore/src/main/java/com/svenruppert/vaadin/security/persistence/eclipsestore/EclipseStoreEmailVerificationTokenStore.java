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

import com.svenruppert.vaadin.security.accountlifecycle.EmailVerificationTokenRecord;
import com.svenruppert.vaadin.security.accountlifecycle.EmailVerificationTokenStore;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link EmailVerificationTokenStore}. */
final class EclipseStoreEmailVerificationTokenStore implements EmailVerificationTokenStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreEmailVerificationTokenStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<EmailVerificationTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().emailVerificationTokens.get(tokenHash));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void save(EmailVerificationTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.lock().writeLock().lock();
    try {
      storage.root().emailVerificationTokens.put(record.tokenHash(), record);
      storage.manager().store(storage.root().emailVerificationTokens);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean markConsumed(String tokenHash, Instant at) {
    requireNonBlank(tokenHash);
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      EmailVerificationTokenRecord prev = storage.root().emailVerificationTokens.get(tokenHash);
      if (prev == null || prev.isConsumed()) {
        return false;
      }
      storage.root().emailVerificationTokens.put(tokenHash, prev.withConsumedAt(at));
      storage.manager().store(storage.root().emailVerificationTokens);
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
      int before = storage.root().emailVerificationTokens.size();
      storage.root().emailVerificationTokens.values().removeIf(record ->
          record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
      int removed = before - storage.root().emailVerificationTokens.size();
      if (removed > 0) {
        storage.manager().store(storage.root().emailVerificationTokens);
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
      int before = storage.root().emailVerificationTokens.size();
      storage.root().emailVerificationTokens.values().removeIf(record -> record.isExpired(now));
      int removed = before - storage.root().emailVerificationTokens.size();
      if (removed > 0) {
        storage.manager().store(storage.root().emailVerificationTokens);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("tokenHash must not be blank");
    }
  }
}
