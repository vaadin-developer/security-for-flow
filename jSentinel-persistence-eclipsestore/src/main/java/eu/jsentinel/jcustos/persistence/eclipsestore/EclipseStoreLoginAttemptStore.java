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

import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJSentinelRoot.LoginAttemptLedger;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link LoginAttemptStore}. */
final class EclipseStoreLoginAttemptStore implements LoginAttemptStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreLoginAttemptStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public void recordFailure(LoginAttemptKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      LoginAttemptLedger prev = storage.root().loginAttempts.get(key);
      LoginAttemptLedger next = prev == null
          ? new LoginAttemptLedger(1, at)
          : new LoginAttemptLedger(prev.count() + 1, at);
      storage.root().loginAttempts.put(key, next);
      storage.manager().store(storage.root().loginAttempts);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int failureCount(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().readLock().lock();
    try {
      LoginAttemptLedger ledger = storage.root().loginAttempts.get(key);
      return ledger == null ? 0 : ledger.count();
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().readLock().lock();
    try {
      LoginAttemptLedger ledger = storage.root().loginAttempts.get(key);
      return ledger == null ? Optional.empty() : Optional.of(ledger.lastFailureAt());
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void reset(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      if (storage.root().loginAttempts.remove(key) != null) {
        storage.manager().store(storage.root().loginAttempts);
      }
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
