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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.rest.openapi.HandlerJSentinelMetadata;
import eu.jsentinel.jcustos.rest.openapi.OpenApiJSentinelMetadataGenerator;
import eu.jsentinel.jcustos.rest.openapi.JSentinelRequirement;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the V00.70 Phase-8d
 * {@link OpenApiJSentinelMetadataGenerator} extracts the same set of
 * {@code @RequiresPermission} annotations that
 * {@code DemoHttpRouter} dispatches against — a regression net for
 * any future re-shuffling of permissions on demo handlers.
 * <p>
 * Demo-only: this is exactly the call a downstream OpenAPI exporter
 * (springdoc, swagger-core, or hand-written JSON) would invoke to
 * surface the {@code security:[{permissions:[...]}]} blocks on each
 * operation.
 */
@DisplayName("OpenApiJSentinelMetadataGenerator — DemoHandlers extraction")
class DemoHandlersOpenApiMetadataTest {

  private static final OpenApiJSentinelMetadataGenerator GENERATOR =
      new OpenApiJSentinelMetadataGenerator();

  @Test
  @DisplayName("metadata reports the demo handler class name + non-empty methods map")
  void classNameAndShape() {
    HandlerJSentinelMetadata metadata = GENERATOR.generate(DemoHandlers.class);

    assertEquals(DemoHandlers.class.getName(), metadata.handlerClassName());
    assertTrue(metadata.classLevel().isEmpty(),
        "DemoHandlers carries no class-level @Requires* annotation");
    assertFalse(metadata.isEmpty(),
        "DemoHandlers must surface per-method requirements");
  }

  @Test
  @DisplayName("each @RequiresPermission handler shows up as a single PERMISSION/ALL requirement")
  void permissionPerHandlerIsExtracted() {
    HandlerJSentinelMetadata metadata = GENERATOR.generate(DemoHandlers.class);
    Map<String, List<JSentinelRequirement>> methods = metadata.methods();

    assertSinglePermission(methods, "listDocuments", "document:read");
    assertSinglePermission(methods, "createDocument", "document:create");
    assertSinglePermission(methods, "deleteDocument", "document:delete");
    assertSinglePermission(methods, "adminStatus", "admin:access");
    assertSinglePermission(methods, "listUsers", "admin:roles");
    assertSinglePermission(methods, "setUserRole", "admin:roles");
    assertSinglePermission(methods, "createUser", "admin:roles");
    assertSinglePermission(methods, "deleteUser", "admin:roles");
    assertSinglePermission(methods, "auditEvents", "audit:read");
  }

  @Test
  @DisplayName("unprotected handlers carry no requirement entry")
  void unprotectedHandlersAreAbsent() {
    HandlerJSentinelMetadata metadata = GENERATOR.generate(DemoHandlers.class);
    Map<String, List<JSentinelRequirement>> methods = metadata.methods();

    // login / me / operations / logout are authenticated-only or public — no @Requires*.
    assertFalse(methods.containsKey("login"),
        "login must carry no @Requires* — handled before authorization");
    assertFalse(methods.containsKey("me"));
    assertFalse(methods.containsKey("operations"));
    assertFalse(methods.containsKey("logout"));
  }

  private static void assertSinglePermission(
      Map<String, List<JSentinelRequirement>> methods,
      String methodName,
      String expectedPermission) {
    List<JSentinelRequirement> reqs = methods.get(methodName);
    assertTrue(reqs != null && !reqs.isEmpty(),
        methodName + " must surface at least one JSentinelRequirement");
    assertEquals(1, reqs.size(),
        methodName + " carries exactly one @Requires* — got " + reqs);
    JSentinelRequirement requirement = reqs.get(0);
    assertEquals(JSentinelRequirement.Scheme.PERMISSION, requirement.scheme(),
        methodName + " requirement scheme");
    assertEquals(JSentinelRequirement.Operator.ALL, requirement.operator(),
        methodName + " requirement operator");
    assertEquals(List.of(expectedPermission), requirement.values(),
        methodName + " requirement values");
  }
}
