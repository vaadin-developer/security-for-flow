package eu.jsentinel.jcustos.events.bus;

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

import eu.jsentinel.jcustos.events.api.CausationId;
import eu.jsentinel.jcustos.events.api.CorrelationId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EnvelopeSignatureBase — length-prefixed framing (R005)")
class EnvelopeSignatureBaseTest {

  @Test
  @DisplayName("each field is length-prefixed (key=<bytes>:value)")
  void framingIsLengthPrefixed() {
    BusFixtures fx = new BusFixtures();
    SignedJCustosEventEnvelope base = fx.publishPipeline().toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope env = BusFixtures.rebuild(base)
        .correlationId(CorrelationId.of("ab")).build();

    String wire = new String(EnvelopeSignatureBase.compute(env), StandardCharsets.UTF_8);
    // "ab" is 2 UTF-8 bytes → the explicit byte length appears before the value.
    // (The pre-R005 framing emitted "correlationId=ab\n" with no length.)
    assertTrue(wire.contains("correlationId=2:ab\n"),
        "expected length-prefixed field, got:\n" + wire);
  }

  @Test
  @DisplayName("a separator-containing value cannot reframe into a neighbouring field")
  void separatorInValueDoesNotCollide() {
    BusFixtures fx = new BusFixtures();
    SignedJCustosEventEnvelope base = fx.publishPipeline().toEnvelope(BusFixtures.event());

    // The id types only reject blank values — a newline + '=' IS accepted, so
    // this is the exact shape the old framing's unenforced invariant assumed away.
    SignedJCustosEventEnvelope a = BusFixtures.rebuild(base)
        .correlationId(CorrelationId.of("a"))
        .causationId(CausationId.of("b")).build();
    SignedJCustosEventEnvelope b = BusFixtures.rebuild(base)
        .correlationId(CorrelationId.of("a\ncausationId=b"))
        .causationId(CausationId.of("b")).build();

    assertFalse(
        Arrays.equals(EnvelopeSignatureBase.compute(a), EnvelopeSignatureBase.compute(b)),
        "distinct envelopes must never share a signature base");
  }
}
