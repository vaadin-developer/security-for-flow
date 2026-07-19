package com.svenruppert.jsentinel.audit.integrity.api;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.List;
import java.util.Optional;

/**
 * Append-only storage of the audit hash chain (Konzept goal 7). The SPI is
 * deliberately dumb: stores validate <em>linkage</em> only — hash
 * computation is single-homed in the chain package's hasher, and hash
 * <em>correctness</em> is the verifier's job. There are <strong>no delete
 * and no update operations by contract</strong>; an implementation that
 * evicts or rewrites entries breaks the tamper-evidence guarantee.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public interface AuditChainStore {

  /** @return the newest entry, or empty for a virgin chain */
  Optional<AuditChainEntry> head();

  /** @return the number of chained entries */
  long size();

  /**
   * Atomic conditional append — the compare-and-swap is expressed through
   * the entry's own linkage fields: the append succeeds only when
   * {@code entry.index() == size()} AND {@code entry.previousEntryHash()}
   * equals the current head's {@code entryHash} (or
   * {@link AuditChainEntry#GENESIS_PREVIOUS_HASH} when the chain is empty).
   *
   * @param entry the fully-hashed entry
   * @return {@code false} on a stale head — the caller re-reads
   *     {@link #head()} and rebuilds the entry; an existing entry is never
   *     replaced
   */
  boolean append(AuditChainEntry entry);

  /**
   * @param fromIndex first index of the page
   * @param maxCount  page bound, must be {@code >= 1}
   * @return an ascending, contiguous page of at most {@code maxCount}
   *     entries starting at {@code fromIndex}; empty when out of range
   * @throws IllegalArgumentException when {@code maxCount < 1} or
   *     {@code fromIndex < 0}
   */
  List<AuditChainEntry> read(long fromIndex, int maxCount);

  /**
   * @param index the entry position
   * @return the entry at {@code index}, or empty when out of range
   */
  Optional<AuditChainEntry> entryAt(long index);
}
