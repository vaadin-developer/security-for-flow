package com.svenruppert.jsentinel.events.codec;

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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventCategory;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    assertEquals("(x=1;y=2)", first,
        "a nested record renders as sorted name=value pairs, not an identity hash");
  }
}
