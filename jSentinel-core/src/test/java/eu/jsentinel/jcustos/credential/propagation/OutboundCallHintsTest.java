/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("OutboundCall — defensive copy of hints")
class OutboundCallHintsTest {

  @Test
  @DisplayName("Mutating the source map after construction does not leak")
  void defensiveCopy() {
    Map<String, String> src = new HashMap<>();
    src.put("scope", "read");
    OutboundCall call = new OutboundCall("Svc", "load", "aud", src);
    src.put("scope", "MUTATED");
    src.put("extra", "added");
    assertEquals("read", call.hints().get("scope"));
    assertEquals(1, call.hints().size());
  }

  @Test
  @DisplayName("Returned hints map is unmodifiable")
  void unmodifiable() {
    OutboundCall call = new OutboundCall("Svc", "m", "", Map.of("k", "v"));
    assertThrows(UnsupportedOperationException.class,
        () -> call.hints().put("k2", "v2"));
  }

  @Test
  @DisplayName("Null components rejected")
  void nullComponentsRejected() {
    assertThrows(NullPointerException.class,
        () -> new OutboundCall(null, "m", "", Map.of()));
    assertThrows(NullPointerException.class,
        () -> new OutboundCall("Svc", null, "", Map.of()));
    assertThrows(NullPointerException.class,
        () -> new OutboundCall("Svc", "m", null, Map.of()));
    assertThrows(NullPointerException.class,
        () -> new OutboundCall("Svc", "m", "", null));
  }
}
