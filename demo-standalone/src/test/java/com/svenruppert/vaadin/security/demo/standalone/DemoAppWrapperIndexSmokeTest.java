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
package com.svenruppert.vaadin.security.demo.standalone;

import com.svenruppert.vaadin.security.dx.diagnostics.GeneratedSecurityWrapper;
import com.svenruppert.vaadin.security.dx.diagnostics.SecurityDiagnostics;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.73 end-to-end smoke check: the security-processor wrote the
 * wrapper index at compile time, the V00.72 reader is on the
 * classpath, and {@link SecurityDiagnostics#inspect()} surfaces
 * {@code MemberDirectorySecured} as a generated wrapper for
 * {@link MemberDirectory}.
 *
 * <p>The test exercises the diagnostic pipeline from the demo's own
 * classpath — exactly the path the CLI uses on startup.
 */
@DisplayName("demo-standalone wrapper-index smoke (V00.73)")
class DemoAppWrapperIndexSmokeTest {

  @Test
  @DisplayName("MemberDirectory appears in SecurityDiagnostics.processorReport().wrappers()")
  void memberDirectoryIsListed() {
    List<GeneratedSecurityWrapper> wrappers =
        SecurityDiagnostics.inspect().processorReport().wrappers();

    assertFalse(wrappers.isEmpty(),
        "expected at least one wrapper entry — the security-processor "
            + "must have written generated-wrappers.idx during compile");

    GeneratedSecurityWrapper memberDir = wrappers.stream()
        .filter(w -> w.sourceType().equals(MemberDirectory.class))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "MemberDirectory not in wrapper index; saw: " + wrappers));

    assertEquals("MemberDirectorySecured",
        memberDir.generatedType().getSimpleName(),
        "expected MemberDirectorySecured as generated type");
    assertTrue(memberDir.delegatedMethods().contains("addMember")
            && memberDir.delegatedMethods().contains("removeMember")
            && memberDir.delegatedMethods().contains("resetAll"),
        "expected addMember/removeMember/resetAll in delegated methods; got: "
            + memberDir.delegatedMethods());
    assertEquals("proxybuilder", memberDir.processor());
    assertEquals("00.11.00", memberDir.proxyBuilderVersion());
  }
}
