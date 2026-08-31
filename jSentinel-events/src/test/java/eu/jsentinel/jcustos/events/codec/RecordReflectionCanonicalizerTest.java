package eu.jsentinel.jcustos.events.codec;

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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventCategory;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RecordReflectionCanonicalizer — component type safety (R016)")
class RecordReflectionCanonicalizerTest {

  private static final Instant AT = Instant.parse("2026-06-24T10:00:00Z");
  private static final RecordReflectionCanonicalizer CANON =
      new RecordReflectionCanonicalizer();

  private static EventMetadata meta() {
    return EventMetadata.create(
        TenantId.DEFAULT, SubjectId.of("alice"), AT, JSentinelEventSeverity.INFO);
  }

  /** A deterministic value-record used as a nested component. */
  record Coords(int x, int y) {
  }

  record NestedEvent(EventMetadata metadata, Coords where) implements JSentinelEvent {
    @Override
    public EventType eventType() {
      return EventType.of("NestedTest");
    }

    @Override
    public JSentinelEventCategory category() {
      return JSentinelEventCategory.RATE_LIMIT;
    }
  }

  /** A nested value-record with two String components — the R01 collision shape. */
  record Pair(String a, String b) {
  }

  record PairEvent(EventMetadata metadata, Pair pair) implements JSentinelEvent {
    @Override
    public EventType eventType() {
      return EventType.of("PairTest");
    }

    @Override
    public JSentinelEventCategory category() {
      return JSentinelEventCategory.RATE_LIMIT;
    }
  }

  /** An event with a nullable top-level String component. */
  record MaybeEvent(EventMetadata metadata, String detail) implements JSentinelEvent {
    @Override
    public EventType eventType() {
      return EventType.of("MaybeTest");
    }

    @Override
    public JSentinelEventCategory category() {
      return JSentinelEventCategory.RATE_LIMIT;
    }
  }

  /** A non-deterministic component: byte[] renders as an identity hash. */
  record BadEvent(EventMetadata metadata, byte[] blob) implements JSentinelEvent {
    @Override
    public EventType eventType() {
      return EventType.of("BadTest");
    }

    @Override
    public JSentinelEventCategory category() {
      return JSentinelEventCategory.RATE_LIMIT;
    }
  }

  @Test
  @DisplayName("a byte[] component is rejected loudly instead of producing an identity hash")
  void rejectsByteArrayComponent() {
    BadEvent event = new BadEvent(meta(), new byte[]{1, 2, 3});
    PayloadCodecException ex = assertThrows(
        PayloadCodecException.class, () -> CANON.canonicalize(event));
    assertTrue(ex.getMessage().contains("non-canonicalizable"),
        "the message must name the offending component type: " + ex.getMessage());
  }

  @Test
  @DisplayName("a nested value-record component canonicalizes deterministically and stably")
  void nestedRecordIsDeterministic() {
    String first = CANON.canonicalize(new NestedEvent(meta(), new Coords(1, 2)))
        .attributes().get("where");
    String second = CANON.canonicalize(new NestedEvent(meta(), new Coords(1, 2)))
        .attributes().get("where");
    assertEquals(first, second, "the same value must render identically every time");
    // Pin updated for R01: nested component values are now length-prefixed
    // (name=<utf8len>:value) — the old unframed (x=1;y=2) form was not
    // injective, see collisionPairsRenderDifferently.
    assertEquals("(x=1:1;y=1:2)", first,
        "a nested record renders as sorted, length-prefixed name=value pairs");
  }

  @Test
  @DisplayName("R01: values containing the separator can no longer be reframed as other components")
  void collisionPairsRenderDifferently() {
    // Under the old unframed rendering both instances collapsed to the
    // identical string (a=x;b=y;b=z) — a genuine injectivity hole in the
    // signed canonical payload.
    String left = CANON.canonicalize(new PairEvent(meta(), new Pair("x;b=y", "z")))
        .attributes().get("pair");
    String right = CANON.canonicalize(new PairEvent(meta(), new Pair("x", "y;b=z")))
        .attributes().get("pair");
    assertNotEquals(left, right, "distinct component values must render distinctly");
    assertEquals("(a=5:x;b=y;b=1:z)", left);
    assertEquals("(a=1:x;b=5:y;b=z)", right);
  }

  @Test
  @DisplayName("R01: a null nested component renders differently from a genuine \"null\" String")
  void nestedNullVersusNullStringDiffer() {
    String withNull = CANON.canonicalize(new PairEvent(meta(), new Pair(null, "z")))
        .attributes().get("pair");
    String withLiteral = CANON.canonicalize(new PairEvent(meta(), new Pair("null", "z")))
        .attributes().get("pair");
    assertNotEquals(withNull, withLiteral);
    // null renders as the bare marker OUTSIDE the length-prefixed form — no
    // String value can produce it (a "null" String frames as 4:null).
    assertEquals("(a=null;b=1:z)", withNull);
    assertEquals("(a=4:null;b=1:z)", withLiteral);
  }

  @Test
  @DisplayName("R01: a null top-level component is omitted, not rendered as the string \"null\"")
  void topLevelNullVersusNullStringDiffer() {
    // The old rendering emitted "null" for a null top-level component,
    // colliding with a genuine "null" String value. Omission makes the two
    // cases unambiguous (present vs. absent key) while keeping every non-null
    // flat-record payload byte-identical.
    var withNull = CANON.canonicalize(new MaybeEvent(meta(), null)).attributes();
    var withLiteral = CANON.canonicalize(new MaybeEvent(meta(), "null")).attributes();
    assertFalse(withNull.containsKey("detail"), "a null component contributes no attribute");
    assertEquals("null", withLiteral.get("detail"));
    assertNotEquals(withNull, withLiteral);
  }

  @Test
  @DisplayName("R01: nested and null renderings are deterministic across runs")
  void framedRenderingIsDeterministic() {
    PairEvent event = new PairEvent(meta(), new Pair(null, "x;b=y"));
    String first = CANON.canonicalize(event).attributes().get("pair");
    String second = CANON.canonicalize(event).attributes().get("pair");
    assertEquals(first, second);
  }
}
