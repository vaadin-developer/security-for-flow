package eu.jsentinel.jcustos.events.sequence;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.EventSequence;

import java.util.Objects;
import java.util.Optional;

/**
 * Pure validator that classifies an incoming sequence against the last accepted
 * one and maps the result to an outcome under a {@link
 * SequenceViolationStrategy} (Konzept §658-§674).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class SequenceValidator {

  /**
   * Classifies an incoming sequence. An empty {@code last} (fresh scope)
   * accepts the incoming sequence as the baseline.
   *
   * @param last the last accepted sequence, if any
   * @param incoming the sequence being validated
   * @return the classification
   */
  public SequenceState classify(Optional<EventSequence> last, EventSequence incoming) {
    Objects.requireNonNull(last, "last");
    Objects.requireNonNull(incoming, "incoming");
    if (last.isEmpty()) {
      return SequenceState.IN_ORDER;
    }
    EventSequence previous = last.get();
    if (incoming.value() == previous.value() + 1) {
      return SequenceState.IN_ORDER;
    }
    if (incoming.value() > previous.value() + 1) {
      return SequenceState.GAP;
    }
    if (incoming.value() == previous.value()) {
      return SequenceState.DUPLICATE;
    }
    return SequenceState.ROLLBACK;
  }

  /**
   * Classifies and maps to an outcome under the given strategy.
   *
   * @param last the last accepted sequence, if any
   * @param incoming the sequence being validated
   * @param strategy how to treat a violation
   * @return the decision
   */
  public SequenceDecision decide(Optional<EventSequence> last, EventSequence incoming,
      SequenceViolationStrategy strategy) {
    Objects.requireNonNull(strategy, "strategy");
    SequenceState state = classify(last, incoming);
    if (state == SequenceState.IN_ORDER) {
      return new SequenceDecision(state, SequenceOutcome.ACCEPT);
    }
    SequenceOutcome outcome = switch (strategy) {
      case REJECT -> SequenceOutcome.REJECT;
      case DEAD_LETTER -> SequenceOutcome.DEAD_LETTER;
      case ACCEPT_WITH_WARNING -> SequenceOutcome.ACCEPT_WITH_WARNING;
    };
    return new SequenceDecision(state, outcome);
  }
}
