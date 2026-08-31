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
 * Signed, verifiable exports of audit-chain ranges:
 * {@link eu.jsentinel.jcustos.audit.integrity.export.AuditBatchSigner}
 * signs a contiguous range into a
 * {@link eu.jsentinel.jcustos.audit.integrity.export.SignedAuditBatch}
 * (the chain binds every entry, the signature binds the chain — using the
 * events key/signature SPIs, no second signing stack),
 * {@link eu.jsentinel.jcustos.audit.integrity.export.AuditExportService}
 * produces exports, and
 * {@link eu.jsentinel.jcustos.audit.integrity.export.AuditExportNdjsonCodec}
 * carries them as {@code application/x-ndjson} — re-verifiable via
 * {@link eu.jsentinel.jcustos.audit.integrity.export.AuditBatchVerifier}
 * with nothing but public key material.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.audit.integrity.export;
