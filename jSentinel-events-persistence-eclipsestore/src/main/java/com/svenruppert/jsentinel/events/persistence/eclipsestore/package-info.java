/*-
 * #%L
 * jSentinel Events — Eclipse-Store persistence
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
 * V00.75 Eclipse-Store persistence for the Security Event Bus (Konzept §1070):
 * JVM-restart-safe {@code ReplayStore}, {@code SequenceStore},
 * {@code EnvelopeStore} and {@code DeadLetterStore} behind the single {@link
 * com.svenruppert.jsentinel.events.persistence.eclipsestore.EclipseStoreEventStorage}
 * facade (one embedded storage, write-lock-serialized). The storage root class
 * stays implementation-internal (Konzept §1079).
 *
 * <p>The optional Java-native Eclipse-Serializer payload codec (plan P014,
 * Konzept §468) is deferred: Eclipse-Store 4.1.0 does not transitively expose
 * the standalone {@code org.eclipse.serializer:serializer} facade, and pinning
 * it risks a version clash with the embedded persistence binary. The required
 * default — the interoperable canonical-JSON codec in {@code jSentinel-events}
 * — is fully shipped and covers the deterministic-bytes contract.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.persistence.eclipsestore;
