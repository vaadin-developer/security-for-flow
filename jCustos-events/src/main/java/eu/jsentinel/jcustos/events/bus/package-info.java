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
 * V00.75 EventBus API + pipelines (Konzept §791-§898): the {@link
 * eu.jsentinel.jcustos.events.bus.JCustosEventBus} contract, its
 * {@link eu.jsentinel.jcustos.events.bus.DefaultJCustosEventBus}
 * implementation, the {@link
 * eu.jsentinel.jcustos.events.bus.PublishPipeline} (event → signed
 * envelope) and {@link eu.jsentinel.jcustos.events.bus.ConsumePipeline}
 * (envelope → {@link
 * eu.jsentinel.jcustos.events.bus.JCustosEventVerificationResult}),
 * plus the {@link
 * eu.jsentinel.jcustos.events.bus.JCustosEventListener} /
 * {@link eu.jsentinel.jcustos.events.bus.JCustosEventListenerOptions} /
 * {@link eu.jsentinel.jcustos.events.bus.Registration} subscription model
 * and {@link eu.jsentinel.jcustos.events.bus.ListenerErrorStrategy}.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.bus;
