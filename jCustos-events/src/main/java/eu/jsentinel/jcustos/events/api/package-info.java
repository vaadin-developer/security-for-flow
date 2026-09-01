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
 * V00.75 Security Event Bus core API: the {@link
 * eu.jsentinel.jcustos.events.api.JCustosEvent} contract, the signed
 * {@link eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope}
 * and its builder, the event category / severity enums, and the strongly
 * typed envelope identifiers ({@code EventId}, {@code EventEnvelopeId},
 * {@code EventProducerId}, {@code CorrelationId}, {@code CausationId},
 * {@code EventSequence}, {@code KeyId}, {@code SignatureAlgorithmId},
 * {@code PayloadContentType}, {@code PayloadHashAlgorithm}).
 *
 * <p>The module is framework-neutral — no Vaadin, no REST framework, no
 * Eclipse Store (Konzept §102). Every public type in this package is
 * annotated {@link
 * eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi}. The
 * V00.76 / V00.77 target named in earlier releases predates this surface,
 * which shipped in V00.75, and is not a commitment. Promotion waits on an
 * audit of the event surface as a whole, including the testkit contract
 * suites — a larger piece of work than the per-type promotions of V00.83
 * and deliberately not bundled with them.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.api;
