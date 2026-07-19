package com.svenruppert.jsentinel.events.wire;

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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

@DisplayName("WireJson — malformed input is contained (H4)")
class WireJsonTest {

  /**
   * Fixed, deterministic corpus of broken inputs (no randomness — Memory
   * discipline). Each must yield {@link EventWireException} or a clean parse;
   * never a raw JDK runtime exception leaking out of the parser.
   */
  private static final List<String> MALFORMED = List.of(
      "",                       // empty
      "{",                      // just an opening brace
      "{\"a\"",                 // key, no colon/value
      "{\"a\" \"b\"}",          // missing colon
      "{\"a\":\"b\"",           // missing closing brace
      "{\"a\":\"b\"}trailing",  // trailing garbage
      "{\"a\":\"x",             // unterminated string
      "{\"a\":\"\\",            // lone backslash at end (truncated escape)
      "{\"a\":\"\\u12\"}",      // truncated \\u (fewer than 4 hex digits)
      "{\"a\":\"\\uZZZZ\"}",    // non-hex \\u
      "{\"a\":\"\\q\"}",        // invalid escape
      "{\"a\":99999999999999999999}", // number overflow (> Long.MAX_VALUE)
      "{\"a\":-}",              // minus with no digits
      "{\"a\":{\"b\":\"c\"}}",  // nested object (engine is flat-object only)
      "{\"a\":}",               // missing value
      "{,}",                    // junk
      "{\"a\":\"b\",}"          // dangling comma
  );

  @Test
  @DisplayName("every malformed input throws EventWireException, never a raw JDK exception")
  void malformedInputsAreContained() {
    for (String bad : MALFORMED) {
      try {
        WireJson.parseObject(bad);
        // a clean parse is an acceptable outcome too — the contract is only
        // "no raw JDK runtime exception escapes".
      } catch (EventWireException expected) {
        // contained — good
      } catch (RuntimeException leaked) {
        fail("input " + quote(bad) + " leaked a non-EventWireException: "
            + leaked.getClass().getName() + ": " + leaked.getMessage());
      }
    }
  }

  @Test
  @DisplayName("a well-formed flat object still round-trips")
  void wellFormedStillParses() {
    Map<String, Object> parsed =
        WireJson.parseObject("{\"name\":\"alice\",\"sequence\":42}");
    assertEquals("alice", parsed.get("name"));
    assertEquals(42L, parsed.get("sequence"));
  }

  @Test
  @DisplayName("a number overflow is reported as EventWireException with the JDK cause attached")
  void numberOverflowKeepsCause() {
    EventWireException ex = catchWire("{\"a\":99999999999999999999}");
    assertInstanceOf(NumberFormatException.class, ex.getCause());
  }

  private static EventWireException catchWire(String json) {
    try {
      WireJson.parseObject(json);
      return fail("expected EventWireException for " + quote(json));
    } catch (EventWireException e) {
      return e;
    }
  }

  private static String quote(String s) {
    return "<<" + s + ">>";
  }
}
