package eu.jsentinel.jcustos.audit.integrity.verify;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * Outcome of an audit-chain verification walk — first break wins.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public sealed interface AuditChainVerificationResult {

  /**
   * Every entry recomputed and linked correctly.
   *
   * @param entryCount the number of verified entries
   * @param headHash   the last verified entry's hash
   */
  record Valid(long entryCount, String headHash) implements AuditChainVerificationResult {
    public Valid {
      if (entryCount < 1) {
        throw new IllegalArgumentException("entryCount must be >= 1 — use Empty");
      }
      Objects.requireNonNull(headHash, "headHash");
    }
  }

  /** Nothing to verify — a virgin chain. */
  record Empty() implements AuditChainVerificationResult {
  }

  /**
   * The chain broke.
   *
   * @param atIndex the index of the first untrustworthy entry
   * @param reason  the break classification
   * @param detail  operator-facing description (expected-vs-found prefixes,
   *                never payload bytes)
   */
  record Broken(long atIndex, AuditChainBreakReason reason, String detail)
      implements AuditChainVerificationResult {
    public Broken {
      Objects.requireNonNull(reason, "reason");
      Objects.requireNonNull(detail, "detail");
    }
  }
}
