package eu.jsentinel.jcustos.events.api;

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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("EventSequence")
class EventSequenceTest {

  @Test
  @DisplayName("next() advances by one")
  void nextAdvances() {
    assertEquals(EventSequence.of(2L), EventSequence.of(1L).next());
  }

  @Test
  @DisplayName("R039: next() throws at Long.MAX_VALUE instead of wrapping to a negative value")
  void nextOverflowThrows() {
    EventSequence max = EventSequence.of(Long.MAX_VALUE);
    assertThrows(ArithmeticException.class, max::next,
        "advancing past Long.MAX_VALUE must throw, not wrap to a negative sequence");
  }
}
