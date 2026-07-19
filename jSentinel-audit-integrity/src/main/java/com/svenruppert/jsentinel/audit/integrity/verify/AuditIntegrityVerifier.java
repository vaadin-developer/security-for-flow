package com.svenruppert.jsentinel.audit.integrity.verify;

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

import com.svenruppert.jsentinel.audit.integrity.api.AuditChainEntry;
import com.svenruppert.jsentinel.audit.integrity.api.AuditChainStore;
import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainEntryHasher;
import com.svenruppert.jsentinel.audit.integrity.verify.AuditChainVerificationResult.Broken;
import com.svenruppert.jsentinel.audit.integrity.verify.AuditChainVerificationResult.Empty;
import com.svenruppert.jsentinel.audit.integrity.verify.AuditChainVerificationResult.Valid;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Walks an audit chain and recomputes every entry — the Konzept goal-7
 * acceptance check ("Tamper-Evident Audit kann Event-Ketten verifizieren").
 * Each entry is recomputed with the digest algorithm recorded <em>in that
 * entry</em> (algorithm agility); an unavailable digest fails closed as
 * {@link AuditChainBreakReason#ALGORITHM_UNAVAILABLE}, never skipped. The
 * range form {@link #verifyEntries(List, String)} is what makes signed
 * exports independently re-verifiable.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class AuditIntegrityVerifier {

  private static final int DEFAULT_PAGE_SIZE = 512;

  private final int pageSize;

  public AuditIntegrityVerifier() {
    this(DEFAULT_PAGE_SIZE);
  }

  public AuditIntegrityVerifier(int pageSize) {
    if (pageSize < 1) {
      throw new IllegalArgumentException("pageSize must be >= 1");
    }
    this.pageSize = pageSize;
  }

  /**
   * @param store the chain store
   * @return the first break, {@link Empty} for a virgin chain, or
   *     {@link Valid} with count and head hash
   */
  public AuditChainVerificationResult verify(AuditChainStore store) {
    Objects.requireNonNull(store, "store");
    String expectedPrevious = AuditChainEntry.GENESIS_PREVIOUS_HASH;
    long expectedIndex = 0;
    long verified = 0;
    String headHash = null;
    while (true) {
      List<AuditChainEntry> page = store.read(expectedIndex, pageSize);
      if (page.isEmpty()) {
        break;
      }
      for (AuditChainEntry entry : page) {
        AuditChainVerificationResult broken =
            checkEntry(entry, expectedIndex, expectedPrevious);
        if (broken != null) {
          return broken;
        }
        expectedPrevious = entry.entryHash();
        headHash = entry.entryHash();
        expectedIndex++;
        verified++;
      }
    }
    return verified == 0 ? new Empty() : new Valid(verified, headHash);
  }

  /**
   * Range verification: checks the entries against each other and anchors
   * the first one to {@code expectedPreviousHash} — pass
   * {@link AuditChainEntry#GENESIS_PREVIOUS_HASH} for a from-genesis range.
   *
   * @param entries              the contiguous range, ascending
   * @param expectedPreviousHash the hash the first entry must link to
   * @return the first break, {@link Empty} for an empty list, or {@link Valid}
   */
  public AuditChainVerificationResult verifyEntries(List<AuditChainEntry> entries,
      String expectedPreviousHash) {
    Objects.requireNonNull(entries, "entries");
    Objects.requireNonNull(expectedPreviousHash, "expectedPreviousHash");
    if (entries.isEmpty()) {
      return new Empty();
    }
    String expectedPrevious = expectedPreviousHash;
    long expectedIndex = entries.get(0).index();
    String headHash = null;
    for (AuditChainEntry entry : entries) {
      AuditChainVerificationResult broken =
          checkEntry(entry, expectedIndex, expectedPrevious);
      if (broken != null) {
        return broken;
      }
      expectedPrevious = entry.entryHash();
      headHash = entry.entryHash();
      expectedIndex++;
    }
    return new Valid(entries.size(), headHash);
  }

  private static AuditChainVerificationResult checkEntry(AuditChainEntry entry,
      long expectedIndex, String expectedPrevious) {
    if (entry.index() != expectedIndex) {
      return new Broken(expectedIndex, AuditChainBreakReason.INDEX_GAP,
          "expected index " + expectedIndex + " but found " + entry.index());
    }
    if (!expectedPrevious.equals(entry.previousEntryHash())) {
      AuditChainBreakReason reason =
          AuditChainEntry.GENESIS_PREVIOUS_HASH.equals(expectedPrevious)
              ? AuditChainBreakReason.GENESIS_VIOLATION
              : AuditChainBreakReason.PREVIOUS_HASH_MISMATCH;
      return new Broken(entry.index(), reason,
          "previous-hash link broken: expected " + prefix(expectedPrevious)
              + " but the entry links to " + prefix(entry.previousEntryHash()));
    }
    Optional<String> recomputed = AuditChainEntryHasher.tryComputeEntryHash(
        entry.index(), entry.appendedAt(), entry.algorithmId(),
        entry.previousEntryHash(), entry.payloadType(), entry.payload());
    if (recomputed.isEmpty()) {
      return new Broken(entry.index(), AuditChainBreakReason.ALGORITHM_UNAVAILABLE,
          "digest '" + entry.algorithmId().value() + "' is unavailable — the entry"
              + " cannot be recomputed; fail closed");
    }
    if (!recomputed.orElseThrow().equals(entry.entryHash())) {
      return new Broken(entry.index(), AuditChainBreakReason.ENTRY_HASH_MISMATCH,
          "stored hash " + prefix(entry.entryHash())
              + " does not match the recomputed " + prefix(recomputed.orElseThrow()));
    }
    return null;
  }

  private static String prefix(String hash) {
    return hash.length() <= 12 ? hash : hash.substring(0, 12) + "…";
  }
}
