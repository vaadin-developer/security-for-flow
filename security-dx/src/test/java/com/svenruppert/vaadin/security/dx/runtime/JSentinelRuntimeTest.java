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
package com.svenruppert.vaadin.security.dx.runtime;

import com.svenruppert.vaadin.security.dx.bootstrap.JSentinelBootstrapException;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JSentinelRuntimeTest {

  @Test
  void servicesAndWarningsAreUnmodifiable() {
    List<RegisteredJSentinelService> services = new ArrayList<>();
    services.add(sample());
    JSentinelRuntime r = new JSentinelRuntime(services, List.of(), JSentinelBootstrapMode.PRODUCTION);

    assertThrows(UnsupportedOperationException.class, () -> r.services().add(sample()));
    assertThrows(UnsupportedOperationException.class,
        () -> r.warnings().add(warning(Severity.WARNING)));
  }

  @Test
  void recordIsDefensivelyCopiedFromInputList() {
    List<RegisteredJSentinelService> services = new ArrayList<>();
    JSentinelRuntime r = new JSentinelRuntime(services, List.of(), JSentinelBootstrapMode.DEVELOPMENT);
    services.add(sample()); // post-construction mutation must not leak
    assertEquals(0, r.services().size());
  }

  @Test
  void modeIsRequired() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelRuntime(List.of(), List.of(), null));
  }

  @Test
  void exceptionExposesWarnings() {
    JSentinelBootstrapWarning w = warning(Severity.ERROR);
    JSentinelBootstrapException ex = new JSentinelBootstrapException(List.of(w));
    assertEquals(1, ex.warnings().size());
    assertSame(w, ex.warnings().get(0));
    assertThrows(UnsupportedOperationException.class, () -> ex.warnings().add(w));
  }

  @Test
  void warningRequiresCodeAndFix() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelBootstrapWarning(Severity.WARNING, null, "msg", "fix"));
    assertThrows(NullPointerException.class,
        () -> new JSentinelBootstrapWarning(Severity.WARNING, "code", "msg", null));
  }

  /**
   * Defensive sanity check: toString() of the records must not contain
   * anything that resembles a credential token. The current record types
   * carry no secret data, but we encode the discipline as a contract.
   */
  @Test
  void toStringDoesNotLeakCredentialLikeTokens() {
    Pattern secretShape = Pattern.compile(
        "(password|secret|token|api[-_]?key|bearer)",
        Pattern.CASE_INSENSITIVE);

    JSentinelRuntime r = new JSentinelRuntime(
        List.of(sample()),
        List.of(warning(Severity.INFO)),
        JSentinelBootstrapMode.STRICT);

    assertNotNull(r.toString());
    assertFalse(secretShape.matcher(r.toString()).find(),
        "JSentinelRuntime.toString() must not look credential-like: " + r);
    assertTrue(r.toString().contains("STRICT"));
  }

  private static RegisteredJSentinelService sample() {
    return new RegisteredJSentinelService(Object.class, String.class, "test", false);
  }

  private static JSentinelBootstrapWarning warning(Severity s) {
    return new JSentinelBootstrapWarning(s, "test-code", "test message", "test fix");
  }
}
