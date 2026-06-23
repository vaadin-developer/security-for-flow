/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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
 * V00.75 envelope + dead-letter stores (Konzept §701-§751): the {@link
 * com.svenruppert.jsentinel.events.store.JSentinelEventEnvelopeStore} (append /
 * findAfter / findByEnvelopeId / count) with its {@link
 * com.svenruppert.jsentinel.events.store.JSentinelEventCursor} and {@link
 * com.svenruppert.jsentinel.events.store.StoredEnvelope}, and the {@link
 * com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetterStore} with
 * its {@link com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetter}
 * record and {@link
 * com.svenruppert.jsentinel.events.store.RejectionReason}. In-memory defaults
 * ship here; Eclipse-Store-backed variants ship in
 * {@code jSentinel-events-persistence-eclipsestore}.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.store;
