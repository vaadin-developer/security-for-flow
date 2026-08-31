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

/**
 * V00.75 replay-protection SPI (Konzept §617-§648): the {@link
 * eu.jsentinel.jcustos.events.replay.JCustosEventReplayStore} contract
 * with its atomic {@code markSeen} and a bounded-LRU {@link
 * eu.jsentinel.jcustos.events.replay.InMemoryReplayStore} default. A
 * JVM-restart-safe variant ships in
 * {@code jCustos-events-persistence-eclipsestore}.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.replay;
