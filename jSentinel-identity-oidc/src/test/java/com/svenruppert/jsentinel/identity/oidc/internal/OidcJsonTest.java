/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.identity.oidc.internal;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OidcJson — strict in-tree JSON parser (no JSON library)")
class OidcJsonTest {

  @Test
  @DisplayName("parses objects, arrays, strings, numbers, booleans and null")
  void parsesAllShapes() {
    Map<String, Object> m = OidcJson.parseObject(
        "{\"s\":\"hi\",\"n\":42,\"d\":1.5,\"b\":true,\"z\":null,\"a\":[\"x\",\"y\"],"
            + "\"o\":{\"k\":\"v\"}}");
    assertEquals("hi", m.get("s"));
    assertEquals(42L, m.get("n"));
    assertEquals(1.5, m.get("d"));
    assertEquals(Boolean.TRUE, m.get("b"));
    assertNull(m.get("z"));
    assertTrue(m.containsKey("z"));
    assertEquals(List.of("x", "y"), m.get("a"));
    assertEquals(Map.of("k", "v"), m.get("o"));
  }

  @Test
  @DisplayName("decodes string escapes including \\uXXXX")
  void decodesEscapes() {
    Map<String, Object> m = OidcJson.parseObject("{\"k\":\"a\\nb\\u0041\\\"c\"}");
    assertEquals("a\nbA\"c", m.get("k"));
  }

  @Test
  @DisplayName("rejects trailing content after the top-level value")
  void rejectsTrailingContent() {
    assertThrows(OidcJson.JsonException.class, () -> OidcJson.parse("{}garbage"));
  }

  @Test
  @DisplayName("rejects malformed input (unterminated string / bad literal / missing colon)")
  void rejectsMalformed() {
    assertThrows(OidcJson.JsonException.class, () -> OidcJson.parse("{\"k\":}"));
    assertThrows(OidcJson.JsonException.class, () -> OidcJson.parse("{\"k\" \"v\"}"));
    assertThrows(OidcJson.JsonException.class, () -> OidcJson.parse("\"unterminated"));
    assertThrows(OidcJson.JsonException.class, () -> OidcJson.parse("tru"));
  }

  @Test
  @DisplayName("caps nesting depth (defence against stack-exhausting input)")
  void capsDepth() {
    StringBuilder deep = new StringBuilder();
    for (int i = 0; i < 200; i++) {
      deep.append("[");
    }
    assertThrows(OidcJson.JsonException.class, () -> OidcJson.parse(deep.toString()));
  }

  @Test
  @DisplayName("parseObject rejects a non-object top-level value")
  void parseObjectRejectsNonObject() {
    assertInstanceOf(OidcJson.JsonException.class,
        assertThrows(OidcJson.JsonException.class, () -> OidcJson.parseObject("[1,2,3]")));
  }
}
