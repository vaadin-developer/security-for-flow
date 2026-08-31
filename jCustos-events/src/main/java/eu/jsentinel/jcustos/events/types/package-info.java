/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

/**
 * V00.75 concrete {@link eu.jsentinel.jcustos.events.api.JCustosEvent}
 * record types (Konzept §215-§294), grouped by category: authentication,
 * authorization / policy, session, role / tenant, token / device,
 * rate-limit / abuse, and bus / integrity.
 *
 * <p>Each event composes an {@link
 * eu.jsentinel.jcustos.events.api.EventMetadata} and declares only its
 * constant {@code eventType()} and {@code category()}. The bus / integrity
 * events keep short names ({@code ReplayDetectedEvent} rather than the
 * Konzept's verbose {@code JCustosEventReplayDetectedEvent}); the package
 * already scopes them.
 *
 * <p>Every public type is annotated {@link
 * eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi}.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.types;
