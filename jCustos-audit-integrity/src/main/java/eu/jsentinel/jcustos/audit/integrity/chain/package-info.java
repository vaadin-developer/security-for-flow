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

/**
 * Hash computation and chain writing:
 * {@link eu.jsentinel.jcustos.audit.integrity.chain.AuditChainEntryHasher}
 * is the single home of the hash-base byte layout,
 * {@link eu.jsentinel.jcustos.audit.integrity.chain.AuditChainAppender}
 * the chain's only writer (linkage-CAS with bounded retry), and
 * {@link eu.jsentinel.jcustos.audit.integrity.chain.InMemoryAuditChainStore}
 * the throw-on-full reference store.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.audit.integrity.chain;
