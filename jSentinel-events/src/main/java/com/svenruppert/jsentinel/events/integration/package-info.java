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
 * V00.75 integration building blocks (Konzept §1029-§1068):
 *
 * <ul>
 *   <li>{@link com.svenruppert.jsentinel.events.integration.AuditEventBusListener}
 *       + {@link com.svenruppert.jsentinel.events.integration.AuditEventMapper}
 *       — audit as a separate bus <em>consumer</em>, mapping bus events to the
 *       core audit model with sink-failure isolation.</li>
 *   <li>{@link com.svenruppert.jsentinel.events.integration.JSentinelEventBusFeatureFlag}
 *       + {@link com.svenruppert.jsentinel.events.integration.FeatureFlaggedEventPublisher}
 *       — gate event emission behind {@code jsentinel.events.bus.enabled} so
 *       legacy direct-audit deployments are unaffected.</li>
 * </ul>
 *
 * <p>These live in {@code jSentinel-events} rather than {@code jSentinel-core}
 * because the dependency direction is events → core; core must not depend on
 * the events module. A host wires these blocks into its session / token /
 * rate-limit code paths.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.integration;
