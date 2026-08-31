package eu.jsentinel.jcustos.events.sequence;

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

import eu.jsentinel.jcustos.events.api.EventSequence;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SequenceValidator")
class SequenceValidatorTest {

  private final SequenceValidator validator = new SequenceValidator();

  @Test
  @DisplayName("a fresh scope accepts the first sequence as baseline")
  void freshScopeInOrder() {
    SequenceDecision d = validator.decide(Optional.empty(), EventSequence.of(7),
        SequenceViolationStrategy.REJECT);
    assertEquals(SequenceState.IN_ORDER, d.state());
    assertEquals(SequenceOutcome.ACCEPT, d.outcome());
    assertTrue(d.accepted());
  }

  @Test
  @DisplayName("the next sequence is in order")
  void nextIsInOrder() {
    assertEquals(SequenceState.IN_ORDER,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(6)));
  }

  @Test
  @DisplayName("a higher-than-expected sequence is a GAP")
  void gapDetected() {
    assertEquals(SequenceState.GAP,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(8)));
  }

  @Test
  @DisplayName("a repeated sequence is a DUPLICATE")
  void duplicateDetected() {
    assertEquals(SequenceState.DUPLICATE,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(5)));
  }

  @Test
  @DisplayName("a lower sequence is a ROLLBACK")
  void rollbackDetected() {
    assertEquals(SequenceState.ROLLBACK,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(3)));
  }

  @Test
  @DisplayName("each strategy maps a violation to its outcome")
  void strategyOutcomes() {
    Optional<EventSequence> last = Optional.of(EventSequence.of(5));
    EventSequence gap = EventSequence.of(8);

    SequenceDecision reject = validator.decide(last, gap, SequenceViolationStrategy.REJECT);
    assertEquals(SequenceOutcome.REJECT, reject.outcome());
    assertFalse(reject.accepted());

    SequenceDecision dead = validator.decide(last, gap, SequenceViolationStrategy.DEAD_LETTER);
    assertEquals(SequenceOutcome.DEAD_LETTER, dead.outcome());
    assertFalse(dead.accepted());

    SequenceDecision warn = validator.decide(last, gap,
        SequenceViolationStrategy.ACCEPT_WITH_WARNING);
    assertEquals(SequenceOutcome.ACCEPT_WITH_WARNING, warn.outcome());
    assertTrue(warn.accepted());
  }
}
