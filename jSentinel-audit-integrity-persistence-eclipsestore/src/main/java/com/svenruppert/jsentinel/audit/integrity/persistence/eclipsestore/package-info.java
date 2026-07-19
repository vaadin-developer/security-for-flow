/*-
 * #%L
 * jSentinel Audit Integrity — Eclipse-Store persistence
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
 * V00.80.00 (Konzept goal 7) Eclipse-Store persistence of the audit hash
 * chain behind the
 * {@link com.svenruppert.jsentinel.audit.integrity.persistence.eclipsestore.EclipseStoreAuditChainStorage}
 * facade: one embedded storage, write-lock-serialized linkage CAS, storage
 * tree hardened owner-only before start (JS-SEC-037). A separate module by
 * design — the base persistence module's dependency graph (core +
 * eclipse-store only) stays untouched, mirroring the events-persistence
 * layout. The storage root stays implementation-internal.
 *
 * @since 00.80.00
 */
package com.svenruppert.jsentinel.audit.integrity.persistence.eclipsestore;
