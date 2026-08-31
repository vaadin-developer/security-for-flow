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
package eu.jsentinel.jcustos.dx.runtime;

import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
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

class JCustosRuntimeTest {

  @Test
  void servicesAndWarningsAreUnmodifiable() {
    List<RegisteredJCustosService> services = new ArrayList<>();
    services.add(sample());
    JCustosRuntime r = new JCustosRuntime(services, List.of(), JCustosBootstrapMode.PRODUCTION);

    assertThrows(UnsupportedOperationException.class, () -> r.services().add(sample()));
    assertThrows(UnsupportedOperationException.class,
        () -> r.warnings().add(warning(Severity.WARNING)));
  }

  @Test
  void recordIsDefensivelyCopiedFromInputList() {
    List<RegisteredJCustosService> services = new ArrayList<>();
    JCustosRuntime r = new JCustosRuntime(services, List.of(), JCustosBootstrapMode.DEVELOPMENT);
    services.add(sample()); // post-construction mutation must not leak
    assertEquals(0, r.services().size());
  }

  @Test
  void modeIsRequired() {
    assertThrows(NullPointerException.class,
        () -> new JCustosRuntime(List.of(), List.of(), null));
  }

  @Test
  void exceptionExposesWarnings() {
    JCustosBootstrapWarning w = warning(Severity.ERROR);
    JCustosBootstrapException ex = new JCustosBootstrapException(List.of(w));
    assertEquals(1, ex.warnings().size());
    assertSame(w, ex.warnings().get(0));
    assertThrows(UnsupportedOperationException.class, () -> ex.warnings().add(w));
  }

  @Test
  void warningRequiresCodeAndFix() {
    assertThrows(NullPointerException.class,
        () -> new JCustosBootstrapWarning(Severity.WARNING, null, "msg", "fix"));
    assertThrows(NullPointerException.class,
        () -> new JCustosBootstrapWarning(Severity.WARNING, "code", "msg", null));
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

    JCustosRuntime r = new JCustosRuntime(
        List.of(sample()),
        List.of(warning(Severity.INFO)),
        JCustosBootstrapMode.STRICT);

    assertNotNull(r.toString());
    assertFalse(secretShape.matcher(r.toString()).find(),
        "JCustosRuntime.toString() must not look credential-like: " + r);
    assertTrue(r.toString().contains("STRICT"));
  }

  private static RegisteredJCustosService sample() {
    return new RegisteredJCustosService(Object.class, String.class, "test", false);
  }

  private static JCustosBootstrapWarning warning(Severity s) {
    return new JCustosBootstrapWarning(s, "test-code", "test message", "test fix");
  }
}
