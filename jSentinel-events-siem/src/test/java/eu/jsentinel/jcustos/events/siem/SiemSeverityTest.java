package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jSentinel Events — SIEM exporter
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

import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("SiemSeverity — numeric 0-10 grades from the record TYPE constants")
class SiemSeverityTest {

  @Test
  @DisplayName("the integrity family maps to its documented grades, everything else to the default")
  void severityTable() {
    assertEquals(10, SiemSeverity.severityFor(ReplayDetectedEvent.TYPE));
    assertEquals(9, SiemSeverity.severityFor(SignatureInvalidEvent.TYPE));
    assertEquals(9, SiemSeverity.severityFor(EnvelopeRejectedEvent.TYPE));
    assertEquals(9, SiemSeverity.severityFor(SequenceViolationEvent.TYPE));
    assertEquals(9, SiemSeverity.severityFor(DeadLetteredEvent.TYPE));
    assertEquals(6, SiemSeverity.severityFor(ListenerFailedEvent.TYPE));
    assertEquals(3, SiemSeverity.severityFor(LoginSucceededEvent.TYPE));
  }
}
