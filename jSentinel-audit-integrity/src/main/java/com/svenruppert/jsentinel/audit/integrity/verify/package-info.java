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

/**
 * Chain verification:
 * {@link com.svenruppert.jsentinel.audit.integrity.verify.AuditIntegrityVerifier}
 * walks a chain (or an exported range) and recomputes every entry with the
 * algorithm recorded in that entry; the sealed
 * {@link com.svenruppert.jsentinel.audit.integrity.verify.AuditChainVerificationResult}
 * reports the first break with its
 * {@link com.svenruppert.jsentinel.audit.integrity.verify.AuditChainBreakReason}.
 *
 * @since 00.80.00
 */
package com.svenruppert.jsentinel.audit.integrity.verify;
