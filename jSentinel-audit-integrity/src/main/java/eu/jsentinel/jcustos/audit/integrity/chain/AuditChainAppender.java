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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The chain's only writer: builds a correctly-hashed
 * {@link AuditChainEntry} on top of the current head and appends it through
 * the store's linkage CAS, retrying on contention. Hashing stays
 * single-homed in {@link AuditChainEntryHasher}; stores never compute
 * digests.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class AuditChainAppender implements HasLogger {

  static final String CODE_APPEND_CONTENTION = "audit-integrity/append-contention";
  /**
   * Consecutive CAS losses WITHOUT observed chain growth before the append
   * gives up. Losing against a growing chain is normal contention and
   * retries indefinitely — the linkage CAS guarantees global progress
   * (a lost CAS means another writer appended). Only a store that refuses
   * appends while the chain stands still is a genuine fault.
   */
  static final int MAX_STALLED_ATTEMPTS = 8;

  private final AuditChainStore store;
  private final PayloadHashAlgorithm algorithmId;
  private final Supplier<Instant> clock;

  /** SHA-256 + system clock defaults. */
  public AuditChainAppender(AuditChainStore store) {
    this(store, PayloadHashAlgorithm.SHA_256, Instant::now);
  }

  public AuditChainAppender(AuditChainStore store, PayloadHashAlgorithm algorithmId,
      Supplier<Instant> clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.algorithmId = Objects.requireNonNull(algorithmId, "algorithmId");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * @param payloadType caller-defined payload discriminator
   * @param payload     the canonical payload bytes
   * @return the appended entry
   * @throws AuditChainException code {@code audit-integrity/append-contention}
   *     when the store refuses {@value #MAX_STALLED_ATTEMPTS} consecutive
   *     appends although the chain is not growing (a broken store — normal
   *     contention against a growing chain retries), or
   *     {@code audit-integrity/algorithm-unavailable} from the hasher
   */
  public AuditChainEntry append(String payloadType, byte[] payload) {
    Objects.requireNonNull(payloadType, "payloadType");
    Objects.requireNonNull(payload, "payload");
    int stalled = 0;
    while (true) {
      Optional<AuditChainEntry> head = store.head();
      long index = store.size();
      String previous = head
          .map(AuditChainEntry::entryHash)
          .orElse(AuditChainEntry.GENESIS_PREVIOUS_HASH);
      Instant appendedAt = clock.get();
      String entryHash = AuditChainEntryHasher.computeEntryHash(
          index, appendedAt, algorithmId, previous, payloadType, payload);
      AuditChainEntry entry = new AuditChainEntry(
          index, appendedAt, algorithmId, previous, entryHash, payloadType, payload);
      if (store.append(entry)) {
        return entry;
      }
      if (store.size() > index) {
        // Another writer appended — normal contention, retry on the new head.
        stalled = 0;
      } else if (++stalled >= MAX_STALLED_ATTEMPTS) {
        throw new AuditChainException(CODE_APPEND_CONTENTION,
            "the store refused " + MAX_STALLED_ATTEMPTS
                + " consecutive appends while the chain stood still"
                + " — the store is rejecting writes");
      }
      Thread.onSpinWait();
    }
  }
}
