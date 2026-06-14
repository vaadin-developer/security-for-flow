/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.dx.runtime.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JsonEncoder (V00.74.10 / Prompt 005)")
class JsonEncoderTest {

  @Test
  void nullValueRendersAsLiteralNull() {
    assertEquals("null", JsonEncoder.encode(null));
  }

  @Test
  void booleansRenderAsLiteralKeywords() {
    assertEquals("true", JsonEncoder.encode(Boolean.TRUE));
    assertEquals("false", JsonEncoder.encode(Boolean.FALSE));
  }

  @Test
  void integerAndLongFloatThroughUnchanged() {
    assertEquals("42", JsonEncoder.encode(42));
    assertEquals("-7", JsonEncoder.encode(-7L));
    assertEquals("3.14", JsonEncoder.encode(3.14));
  }

  @Test
  void nonFiniteDoubleIsRejected() {
    assertThrows(JsonEncodeException.class, () -> JsonEncoder.encode(Double.NaN));
    assertThrows(JsonEncodeException.class, () -> JsonEncoder.encode(Double.POSITIVE_INFINITY));
    assertThrows(JsonEncodeException.class, () -> JsonEncoder.encode(Double.NEGATIVE_INFINITY));
  }

  @Test
  void emptyStringRendersAsEmptyQuotes() {
    assertEquals("\"\"", JsonEncoder.encode(""));
  }

  @Test
  void stringEscapesQuoteAndBackslash() {
    assertEquals("\"a\\\"b\\\\c\"", JsonEncoder.encode("a\"b\\c"));
  }

  @Test
  void stringEscapesControlCharactersPerRfc8259() {
    assertEquals("\"\\b\\f\\n\\r\\t\"", JsonEncoder.encode("\b\f\n\r\t"));
  }

  @Test
  void stringEscapesOtherControlsViaUnicodeEscape() {
    assertEquals("\"\\u0001\\u001f\"", JsonEncoder.encode(""));
  }

  @Test
  void emptyArrayRendersAsBrackets() {
    assertEquals("[]", JsonEncoder.encode(List.of()));
  }

  @Test
  void arrayOfMixedScalars() {
    assertEquals("[1,\"two\",true,null]",
        JsonEncoder.encode(java.util.Arrays.asList(1, "two", true, null)));
  }

  @Test
  void emptyObjectRendersAsBraces() {
    assertEquals("{}", JsonEncoder.encode(Map.of()));
  }

  @Test
  void objectPreservesInsertionOrderViaLinkedHashMap() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("z", 1);
    m.put("a", 2);
    m.put("m", 3);
    assertEquals("{\"z\":1,\"a\":2,\"m\":3}", JsonEncoder.encode(m));
  }

  @Test
  void nestedObjectsAndArrays() {
    Map<String, Object> inner = new LinkedHashMap<>();
    inner.put("hits", 7);
    inner.put("ok", true);
    Map<String, Object> outer = new LinkedHashMap<>();
    outer.put("items", List.of(inner));
    outer.put("note", "x");
    assertEquals("{\"items\":[{\"hits\":7,\"ok\":true}],\"note\":\"x\"}",
        JsonEncoder.encode(outer));
  }

  @Test
  void nullObjectKeyIsRejected() {
    Map<Object, Object> m = new java.util.HashMap<>();
    m.put(null, "x");
    JsonEncodeException ex = assertThrows(JsonEncodeException.class,
        () -> JsonEncoder.encode(m));
    assertTrue(ex.getMessage().contains("key must not be null"));
  }

  @Test
  void unsupportedTypeNamesTheOffender() {
    JsonEncodeException ex = assertThrows(JsonEncodeException.class,
        () -> JsonEncoder.encode(new Object()));
    assertTrue(ex.getMessage().contains("java.lang.Object"));
  }
}
