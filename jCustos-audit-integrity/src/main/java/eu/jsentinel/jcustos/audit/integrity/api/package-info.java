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
 * V00.80.00 (Konzept goal 7) tamper-evident audit — the chain model and the
 * append-only {@link eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore}
 * SPI.
 *
 * <p>Separation of duties (Konzept): the Security Event Bus signature
 * provides authenticity and integrity of an event <em>in transport</em>;
 * the audit hash chain provides the tamper-resistant <em>historical
 * record</em>. The chain complements the persistent audit of V00.70 — it
 * does not replace it.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.audit.integrity.api;
