package eu.jsentinel.jcustos.audit.integrity.chain;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * In-memory reference implementation of {@link AuditChainStore} for tests
 * and development; production deployments use the Eclipse-Store-backed
 * implementation. Capacity-bounded via {@link CapacityBound} — and because
 * the chain is append-only, a full store <strong>throws</strong> instead of
 * evicting (evicting the oldest entry would sever the genesis anchor and
 * destroy the tamper evidence); callers isolate the failure like any audit
 * sink failure.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class InMemoryAuditChainStore implements AuditChainStore {

  static final String CODE_CAPACITY_EXCEEDED =
      CapacityBound.capacityExceededCode("audit-integrity/chain-store");

  private final List<AuditChainEntry> entries = new ArrayList<>();
  private final int capacity;

  public InMemoryAuditChainStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  public InMemoryAuditChainStore(int capacity) {
    this.capacity = CapacityBound.requirePositiveCapacity(capacity);
  }

  @Override
  public synchronized Optional<AuditChainEntry> head() {
    return entries.isEmpty()
        ? Optional.empty()
        : Optional.of(entries.get(entries.size() - 1));
  }

  @Override
  public synchronized long size() {
    return entries.size();
  }

  @Override
  public synchronized boolean append(AuditChainEntry entry) {
    if (entry.index() != entries.size()) {
      return false;
    }
    String expectedPrevious = entries.isEmpty()
        ? AuditChainEntry.GENESIS_PREVIOUS_HASH
        : entries.get(entries.size() - 1).entryHash();
    if (!expectedPrevious.equals(entry.previousEntryHash())) {
      return false;
    }
    if (entries.size() >= capacity) {
      throw new AuditChainException(CODE_CAPACITY_EXCEEDED,
          "chain store is full (" + capacity + " entries) — archive the chain"
              + " to persistent storage or raise the capacity");
    }
    entries.add(entry);
    return true;
  }

  @Override
  public synchronized List<AuditChainEntry> read(long fromIndex, int maxCount) {
    if (fromIndex < 0) {
      throw new IllegalArgumentException("fromIndex must be >= 0");
    }
    if (maxCount < 1) {
      throw new IllegalArgumentException("maxCount must be >= 1");
    }
    if (fromIndex >= entries.size()) {
      return List.of();
    }
    int from = (int) fromIndex;
    int to = (int) Math.min(entries.size(), fromIndex + maxCount);
    return List.copyOf(entries.subList(from, to));
  }

  @Override
  public synchronized Optional<AuditChainEntry> entryAt(long index) {
    if (index < 0 || index >= entries.size()) {
      return Optional.empty();
    }
    return Optional.of(entries.get((int) index));
  }
}
