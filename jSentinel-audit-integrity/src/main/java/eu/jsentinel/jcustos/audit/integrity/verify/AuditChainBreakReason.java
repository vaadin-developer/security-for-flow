package eu.jsentinel.jcustos.audit.integrity.verify;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Why a chain walk stopped trusting the chain.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public enum AuditChainBreakReason {

  /** The recomputed entry hash differs from the stored one — the entry was mutated. */
  ENTRY_HASH_MISMATCH,

  /** The entry's previous-hash link does not match its predecessor — an entry was replaced. */
  PREVIOUS_HASH_MISMATCH,

  /** The indices are not contiguous — an entry was removed or reordered. */
  INDEX_GAP,

  /** The first entry does not anchor to the expected genesis/previous hash. */
  GENESIS_VIOLATION,

  /** The entry's digest algorithm is unavailable — fail closed, never skip. */
  ALGORITHM_UNAVAILABLE
}
