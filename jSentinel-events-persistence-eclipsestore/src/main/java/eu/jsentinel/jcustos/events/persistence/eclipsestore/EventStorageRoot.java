package eu.jsentinel.jcustos.events.persistence.eclipsestore;

/*-
 * #%L
 * jCustos Events — Eclipse-Store persistence
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

import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implementation-internal Eclipse-Store root for the event-bus persistent
 * stores (Konzept §1079 — the root stays internal, never part of the public
 * API). Holds the data for all four stores in one storage.
 */
final class EventStorageRoot {

  /** envelopeId -> expiry epoch-milli, for replay protection. */
  final Map<String, Long> seenEnvelopes = new LinkedHashMap<>();

  /**
   * Framed {@code v2:<utf8-len>:<tenant>|<utf8-len>:<producer>} key -> last
   * accepted sequence value (R03; legacy raw {@code tenant|producer} keys are
   * migrated at open by {@code EclipseStoreSequenceStore}).
   */
  final Map<String, Long> sequences = new LinkedHashMap<>();

  /** Append-ordered envelope store; index + 1 is the cursor position. */
  final List<SignedJCustosEventEnvelope> envelopes = new ArrayList<>();

  /** dead-letter id -> record, insertion-ordered. */
  final Map<String, JCustosEventDeadLetter> deadLetters = new LinkedHashMap<>();

  /** Ids of resolved dead letters. */
  final Set<String> resolvedDeadLetters = new LinkedHashSet<>();
}
