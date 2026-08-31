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

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosRuntimeLogTest {

  private static final Pattern SECRET_SHAPE = Pattern.compile(
      "(password|secret|token|api[-_]?key|bearer)",
      Pattern.CASE_INSENSITIVE);

  @Test
  void logContainsModeAndService() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(new RegisteredJCustosService(
            Object.class, String.class, "bootstrap-explicit", false)),
        List.of(),
        JCustosBootstrapMode.PRODUCTION);

    String out = r.log();
    assertTrue(out.contains("mode = PRODUCTION"));
    assertTrue(out.contains("Object"));           // simple name of SPI
    assertTrue(out.contains("java.lang.String")); // FQN of impl
    assertTrue(out.contains("Warnings: 0"));
  }

  @Test
  void emptyRuntimeStillEndsWithNewline() {
    JCustosRuntime r = new JCustosRuntime(List.of(), List.of(),
        JCustosBootstrapMode.DEVELOPMENT);
    String out = r.log();
    assertTrue(out.endsWith("\n"));
    assertTrue(out.contains("(none)"));
    assertTrue(out.contains("Warnings: 0"));
  }

  @Test
  void logRendersEveryWarningCode() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(
            new JCustosBootstrapWarning(
                Severity.ERROR, "missing-authentication-service",
                "no auth", "register one"),
            new JCustosBootstrapWarning(
                Severity.WARNING, "duplicate-service",
                "two impls", "select one")),
        JCustosBootstrapMode.PRODUCTION);

    String out = r.log();
    assertTrue(out.contains("missing-authentication-service"));
    assertTrue(out.contains("duplicate-service"));
    assertTrue(out.contains("[ERROR]"));
    assertTrue(out.contains("[WARNING]"));
  }

  @Test
  void logOutputContainsNoSecretLikeTokens() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(new RegisteredJCustosService(
            Object.class, String.class, "bootstrap-default", true)),
        List.of(new JCustosBootstrapWarning(
            Severity.INFO, "informational-code",
            "informational only", "no fix needed")),
        JCustosBootstrapMode.STRICT);

    String out = r.log();
    assertFalse(SECRET_SHAPE.matcher(out).find(),
        "JCustosRuntime.log() must not look credential-like: " + out);
  }
}
