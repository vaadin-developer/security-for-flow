package eu.jsentinel.jcustos.audit.integrity.export;

/*-
 * #%L
 * jCustos Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.keys.JCustosEventSigningKeyProvider;
import eu.jsentinel.jcustos.events.keys.SigningKeySnapshot;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Signs a contiguous audit-chain range into a {@link SignedAuditBatch},
 * reusing the events key SPIs — no second signing stack: the
 * {@link JCustosEventSigningKeyProvider} (and its atomic
 * {@link SigningKeySnapshot}) is the single signing home of the framework.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class AuditBatchSigner {

  private final JCustosEventSigningKeyProvider signingKeys;
  private final Supplier<Instant> clock;

  public AuditBatchSigner(JCustosEventSigningKeyProvider signingKeys) {
    this(signingKeys, Instant::now);
  }

  public AuditBatchSigner(JCustosEventSigningKeyProvider signingKeys,
      Supplier<Instant> clock) {
    this.signingKeys = Objects.requireNonNull(signingKeys, "signingKeys");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * @param entries a non-empty, contiguous, ascending chain range
   * @return the signed batch
   * @throws IllegalArgumentException when the range is empty, unordered or
   *     has gaps
   */
  public SignedAuditBatch sign(List<AuditChainEntry> entries) {
    Objects.requireNonNull(entries, "entries");
    if (entries.isEmpty()) {
      throw new IllegalArgumentException("cannot sign an empty range");
    }
    for (int i = 1; i < entries.size(); i++) {
      if (entries.get(i).index() != entries.get(i - 1).index() + 1) {
        throw new IllegalArgumentException("the range must be contiguous and"
            + " ascending — gap after index " + entries.get(i - 1).index());
      }
    }
    AuditChainEntry first = entries.get(0);
    AuditChainEntry last = entries.get(entries.size() - 1);
    Instant signedAt = clock.get();
    // One atomic snapshot per batch: keyId, algorithm and private key can
    // never come from two different rotation states (R00 discipline).
    SigningKeySnapshot snapshot = signingKeys.signingSnapshot();
    byte[] base = AuditBatchSignatureBase.compute(
        first.index(), last.index(), entries.size(),
        first.previousEntryHash(), last.entryHash(), signedAt,
        snapshot.keyId(), snapshot.algorithm().id());
    byte[] signature = snapshot.algorithm().sign(base, snapshot.privateKey());
    return new SignedAuditBatch(first.index(), last.index(), entries.size(),
        first.previousEntryHash(), last.entryHash(), signedAt,
        snapshot.keyId(), snapshot.algorithm().id(), signature);
  }
}
