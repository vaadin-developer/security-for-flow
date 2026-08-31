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
 * The two feeds of the audit chain:
 * {@link eu.jsentinel.jcustos.audit.integrity.listener.AuditIntegrityListener}
 * chains audit-relevant Security Event Bus events (filtered by
 * {@link eu.jsentinel.jcustos.audit.integrity.listener.AuditRelevancePolicy})
 * and
 * {@link eu.jsentinel.jcustos.audit.integrity.listener.HashChainingAuditSink}
 * chains core audit events alongside the existing V00.70 sinks. Both are
 * strictly failure-isolated — a broken chain never breaks dispatch or the
 * audit fan-out.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.audit.integrity.listener;
