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
package com.svenruppert.vaadin.security.rest.openapi;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OpenApiSecurityMetadataGenerator")
class OpenApiSecurityMetadataGeneratorTest {

  private final OpenApiSecurityMetadataGenerator gen = new OpenApiSecurityMetadataGenerator();

  static class UnannotatedHandler {
    public void list() {}
  }

  @RequiresRole({"ADMIN"})
  static class ClassLevelHandler {
    public void onlyClass() {}

    @RequiresPermission("document:read")
    public void read() {}
  }

  static class MethodLevelHandler {
    @RequiresPermission("document:read")
    public void read() {}

    @RequiresAllPermissions({"document:write", "audit:emit"})
    public void writeAndAudit() {}

    @RequiresAnyPermission({"document:share", "document:export"})
    public void shareOrExport() {}

    @RequiresRole("EDITOR")
    public void editorOnly() {}

    @RequiresPolicy("document.delete")
    public void deletePolicy() {}
  }

  @RequiresRole("ADMIN")
  @RequiresPermission("admin:any")
  static class CompositeHandler {
    @RequiresPermission("audit:emit")
    @RequiresPolicy("audit.gate")
    public void touch() {}

    private void privateHelper() {} // included as non-static — generator still scans it
  }

  @Test
  @DisplayName("unannotated handler → empty metadata")
  void unannotatedHandlerIsEmpty() {
    HandlerSecurityMetadata md = gen.generate(UnannotatedHandler.class);
    assertEquals(UnannotatedHandler.class.getName(), md.handlerClassName());
    assertTrue(md.classLevel().isEmpty());
    assertTrue(md.methods().isEmpty());
    assertTrue(md.isEmpty());
  }

  @Test
  @DisplayName("class-level @RequiresRole is captured; method-level entries are independent")
  void classLevelAnnotation() {
    HandlerSecurityMetadata md = gen.generate(ClassLevelHandler.class);

    assertEquals(1, md.classLevel().size());
    SecurityRequirement classReq = md.classLevel().get(0);
    assertEquals(SecurityRequirement.Scheme.ROLE, classReq.scheme());
    assertEquals(SecurityRequirement.Operator.ALL, classReq.operator());
    assertEquals(List.of("ADMIN"), classReq.values());

    // only annotated methods produce method entries
    assertTrue(md.methods().containsKey("read"));
    assertFalse(md.methods().containsKey("onlyClass"));
    assertEquals(SecurityRequirement.Scheme.PERMISSION,
        md.methods().get("read").get(0).scheme());
  }

  @Test
  @DisplayName("every annotation kind maps to the documented Scheme + Operator")
  void everyAnnotationKindMaps() {
    HandlerSecurityMetadata md = gen.generate(MethodLevelHandler.class);

    SecurityRequirement read = md.methods().get("read").get(0);
    assertEquals(SecurityRequirement.Scheme.PERMISSION, read.scheme());
    assertEquals(SecurityRequirement.Operator.ALL, read.operator());
    assertEquals(List.of("document:read"), read.values());

    SecurityRequirement wa = md.methods().get("writeAndAudit").get(0);
    assertEquals(SecurityRequirement.Scheme.PERMISSION, wa.scheme());
    assertEquals(SecurityRequirement.Operator.ALL, wa.operator());
    assertEquals(List.of("document:write", "audit:emit"), wa.values());

    SecurityRequirement so = md.methods().get("shareOrExport").get(0);
    assertEquals(SecurityRequirement.Scheme.PERMISSION, so.scheme());
    assertEquals(SecurityRequirement.Operator.ANY, so.operator());
    assertEquals(List.of("document:share", "document:export"), so.values());

    SecurityRequirement eo = md.methods().get("editorOnly").get(0);
    assertEquals(SecurityRequirement.Scheme.ROLE, eo.scheme());
    assertEquals(SecurityRequirement.Operator.ALL, eo.operator());
    assertEquals(List.of("EDITOR"), eo.values());

    SecurityRequirement dp = md.methods().get("deletePolicy").get(0);
    assertEquals(SecurityRequirement.Scheme.POLICY, dp.scheme());
    assertEquals(SecurityRequirement.Operator.ALL, dp.operator());
    assertEquals(List.of("document.delete"), dp.values());
  }

  @Test
  @DisplayName("class-level and method-level annotations are both surfaced; AND-composition is left to the consumer")
  void classAndMethodComposed() {
    HandlerSecurityMetadata md = gen.generate(CompositeHandler.class);

    // Two class-level requirements: one role + one permission
    assertEquals(2, md.classLevel().size());

    // The touch() method adds two more
    List<SecurityRequirement> touch = md.methods().get("touch");
    assertEquals(2, touch.size());
  }

  @Test
  @DisplayName("methods map is immutable")
  void methodsImmutable() {
    HandlerSecurityMetadata md = gen.generate(MethodLevelHandler.class);
    assertThrows(UnsupportedOperationException.class,
        () -> md.methods().put("x", List.of()));
    assertThrows(UnsupportedOperationException.class,
        () -> md.classLevel().add(null));
  }

  @Test
  @DisplayName("SecurityRequirement record invariants are enforced")
  void requirementInvariants() {
    assertThrows(NullPointerException.class,
        () -> new SecurityRequirement(null,
            SecurityRequirement.Operator.ALL, List.of("x")));
    assertThrows(NullPointerException.class,
        () -> new SecurityRequirement(SecurityRequirement.Scheme.ROLE, null, List.of("x")));
    assertThrows(NullPointerException.class,
        () -> new SecurityRequirement(SecurityRequirement.Scheme.ROLE,
            SecurityRequirement.Operator.ALL, null));
    assertThrows(IllegalArgumentException.class,
        () -> new SecurityRequirement(SecurityRequirement.Scheme.ROLE,
            SecurityRequirement.Operator.ALL, List.of()));
    assertThrows(IllegalArgumentException.class,
        () -> new SecurityRequirement(SecurityRequirement.Scheme.ROLE,
            SecurityRequirement.Operator.ALL, java.util.Arrays.asList("", "x")));
  }

  @Test
  @DisplayName("HandlerSecurityMetadata invariants are enforced")
  void metadataInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new HandlerSecurityMetadata("", List.of(), java.util.Map.of()));
    assertThrows(NullPointerException.class,
        () -> new HandlerSecurityMetadata("X", null, java.util.Map.of()));
    assertThrows(NullPointerException.class,
        () -> new HandlerSecurityMetadata("X", List.of(), null));

    java.util.Map<String, List<SecurityRequirement>> badKey = new java.util.HashMap<>();
    badKey.put("", List.of());
    assertThrows(IllegalArgumentException.class,
        () -> new HandlerSecurityMetadata("X", List.of(), badKey));
  }

  @Test
  @DisplayName("null arguments are rejected")
  void rejectNulls() {
    assertThrows(NullPointerException.class, () -> gen.generate(null));
  }
}
