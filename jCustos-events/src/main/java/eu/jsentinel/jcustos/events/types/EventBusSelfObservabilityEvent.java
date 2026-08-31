package eu.jsentinel.jcustos.events.types;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.JCustosEvent;

/**
 * Marker for the events the Security Event Bus emits about <em>itself</em>:
 * {@link EnvelopeRejectedEvent}, {@link ReplayDetectedEvent},
 * {@link SignatureInvalidEvent}, {@link SequenceViolationEvent},
 * {@link ListenerFailedEvent} and {@link DeadLetteredEvent} (Konzept §8,
 * "EventBus-Fehler werden selbst beobachtbar").
 *
 * <p>Self-observability events describe the bus, not the application. They are
 * dispatched <em>directly</em> to subscribed listeners — never through the
 * signed {@code PublishPipeline}: no producer policy is consulted, no sequence
 * is reserved, no signature is created, no replay marking happens, and nothing
 * is appended to an envelope store. This structurally prevents rejection
 * loops — a failure event can never itself be rejected, so it can never spawn
 * a further failure event about its own rejection.
 *
 * <p>Because they never enter the publish pipeline, self-observability events
 * are excluded from the {@code security.eventbus.published.total} metric by
 * the monitoring bridge; they feed the dedicated rejection / failure metric
 * family instead.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public interface EventBusSelfObservabilityEvent extends JCustosEvent {
}
