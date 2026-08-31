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

import eu.jsentinel.jcustos.audit.integrity.verify.AuditChainVerificationResult;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.KeyId;

import java.util.Objects;

/**
 * Outcome of verifying a {@link SignedAuditBatch} against its entries.
 * Ordering of the checks: chain first (an interior tamper is reported as
 * {@link ChainBroken} regardless of the signature), then range consistency,
 * then key resolution, then the signature itself.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public sealed interface AuditBatchVerificationResult {

  /** Chain, range, key and signature all check out. */
  record Valid(long entryCount, String batchHeadHash)
      implements AuditBatchVerificationResult {
    public Valid {
      Objects.requireNonNull(batchHeadHash, "batchHeadHash");
    }
  }

  /** The entry range itself is broken — see the chain result for the index. */
  record ChainBroken(AuditChainVerificationResult.Broken cause)
      implements AuditBatchVerificationResult {
    public ChainBroken {
      Objects.requireNonNull(cause, "cause");
    }
  }

  /** The entries do not match the batch's declared range/head. */
  record RangeMismatch(String detail) implements AuditBatchVerificationResult {
    public RangeMismatch {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /** The signing key cannot be resolved. */
  record UnknownKey(KeyId keyId) implements AuditBatchVerificationResult {
    public UnknownKey {
      Objects.requireNonNull(keyId, "keyId");
    }
  }

  /** The signing key is revoked — batches under it are rejected. */
  record KeyRevoked(KeyId keyId) implements AuditBatchVerificationResult {
    public KeyRevoked {
      Objects.requireNonNull(keyId, "keyId");
    }
  }

  /** The signature does not verify (or its algorithm is unsupported). */
  record SignatureInvalid(String reason) implements AuditBatchVerificationResult {
    public SignatureInvalid {
      Objects.requireNonNull(reason, "reason");
    }
  }
}
