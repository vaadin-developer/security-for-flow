package com.svenruppert.jsentinel.audit.integrity.export;

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
import com.svenruppert.jsentinel.audit.integrity.verify.AuditChainVerificationResult;
import com.svenruppert.jsentinel.audit.integrity.verify.AuditIntegrityVerifier;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.keys.JSentinelEventVerificationKeyResolver;
import com.svenruppert.jsentinel.events.keys.KeyStatus;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithm;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithms;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Verifies a {@link SignedAuditBatch} against its entry range using only
 * public material — the check an auditor runs on an export they received.
 * Rotated-out keys with status {@link KeyStatus#ACCEPTED_FOR_VERIFICATION}
 * or {@link KeyStatus#EXPIRED} still verify (historical batches must remain
 * checkable after rotation); {@link KeyStatus#REVOKED} does not. An
 * unsupported algorithm id resolves softly to
 * {@link AuditBatchVerificationResult.SignatureInvalid} — never an exception
 * on attacker-influenced input (JS-SEC-054 posture).
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class AuditBatchVerifier {

  private final JSentinelEventVerificationKeyResolver keyResolver;
  private final SignatureAlgorithms algorithms;
  private final AuditIntegrityVerifier chainVerifier = new AuditIntegrityVerifier();

  public AuditBatchVerifier(JSentinelEventVerificationKeyResolver keyResolver,
      SignatureAlgorithms algorithms) {
    this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
    this.algorithms = Objects.requireNonNull(algorithms, "algorithms");
  }

  /**
   * @param batch   the signed statement
   * @param entries the accompanying chain range
   * @return the first failing check, or {@code Valid}
   */
  public AuditBatchVerificationResult verify(SignedAuditBatch batch,
      List<AuditChainEntry> entries) {
    Objects.requireNonNull(batch, "batch");
    Objects.requireNonNull(entries, "entries");

    AuditChainVerificationResult chain =
        chainVerifier.verifyEntries(entries, batch.firstPreviousHash());
    if (chain instanceof AuditChainVerificationResult.Broken broken) {
      return new AuditBatchVerificationResult.ChainBroken(broken);
    }
    if (chain instanceof AuditChainVerificationResult.Empty) {
      return new AuditBatchVerificationResult.RangeMismatch(
          "the batch declares " + batch.entryCount() + " entries but none were supplied");
    }

    AuditChainEntry first = entries.get(0);
    AuditChainEntry last = entries.get(entries.size() - 1);
    if (entries.size() != batch.entryCount()
        || first.index() != batch.fromIndex()
        || last.index() != batch.toIndex()) {
      return new AuditBatchVerificationResult.RangeMismatch(
          "entries [" + first.index() + ", " + last.index() + "] ("
              + entries.size() + ") do not match the declared range ["
              + batch.fromIndex() + ", " + batch.toIndex() + "] ("
              + batch.entryCount() + ")");
    }
    if (!last.entryHash().equals(batch.batchHeadHash())) {
      return new AuditBatchVerificationResult.RangeMismatch(
          "the last entry's hash does not match the declared batch head");
    }

    Optional<PublicKey> publicKey = keyResolver.resolveVerificationKey(batch.keyId());
    if (publicKey.isEmpty()) {
      return new AuditBatchVerificationResult.UnknownKey(batch.keyId());
    }
    if (keyResolver.keyStatus(batch.keyId()) == KeyStatus.REVOKED) {
      return new AuditBatchVerificationResult.KeyRevoked(batch.keyId());
    }

    Optional<SignatureAlgorithm> algorithm = algorithms.find(batch.signatureAlgorithm());
    if (algorithm.isEmpty()) {
      return new AuditBatchVerificationResult.SignatureInvalid(
          "unsupported signature algorithm '" + batch.signatureAlgorithm().value() + "'");
    }
    byte[] base = AuditBatchSignatureBase.compute(
        batch.fromIndex(), batch.toIndex(), batch.entryCount(),
        batch.firstPreviousHash(), batch.batchHeadHash(), batch.signedAt(),
        batch.keyId(), batch.signatureAlgorithm());
    boolean verified;
    try {
      verified = algorithm.orElseThrow()
          .verify(base, batch.signature(), publicKey.orElseThrow());
    } catch (RuntimeException ex) {
      // Fail closed: a structurally hostile signature must never escalate.
      verified = false;
    }
    if (!verified) {
      return new AuditBatchVerificationResult.SignatureInvalid(
          "the batch signature does not verify under key '"
              + batch.keyId().value() + "'");
    }
    return new AuditBatchVerificationResult.Valid(batch.entryCount(), batch.batchHeadHash());
  }
}
