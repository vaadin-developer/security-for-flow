/*-
 * #%L
 * jSentinel Events — Testkit
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
 * V00.75 Security Event Bus testkit: persistence-tech-agnostic
 * {@code @Test default} contract suites for the event-store SPIs — {@link
 * eu.jsentinel.jcustos.events.testkit.ReplayStoreContract}, {@link
 * eu.jsentinel.jcustos.events.testkit.SequenceStoreContract}, {@link
 * eu.jsentinel.jcustos.events.testkit.EnvelopeStoreContract}, {@link
 * eu.jsentinel.jcustos.events.testkit.DeadLetterStoreContract} — plus
 * shared {@link eu.jsentinel.jcustos.events.testkit.TestkitEnvelopes}
 * fixtures. A concrete store test implements the contract and supplies the
 * store under test via the abstract factory method; JUnit 5 discovers the
 * default test methods automatically.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.testkit;
