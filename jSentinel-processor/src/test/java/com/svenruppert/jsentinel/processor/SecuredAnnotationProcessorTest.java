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
package com.svenruppert.jsentinel.processor;

import com.google.testing.compile.Compilation;
import com.google.testing.compile.Compiler;
import com.google.testing.compile.JavaFileObjects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.tools.JavaFileObject;

import static com.google.testing.compile.CompilationSubject.assertThat;

@DisplayName("SecuredAnnotationProcessor — generated wrapper sources")
class SecuredAnnotationProcessorTest {

  private Compilation compile(JavaFileObject... sources) {
    return Compiler.javac()
        .withProcessors(new SecuredAnnotationProcessor())
        .compile(sources);
  }

  // ── positive cases ───────────────────────────────────────────────

  @Test
  @DisplayName("@RequiresPermission(\"doc:delete\") generates requirePermission(\"doc:delete\") + super-call")
  void singlePermissionGeneratesEnforcerCall() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DocService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class DocService {",
        "    @RequiresPermission(\"doc:delete\")",
        "    public void delete(final String id) {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeededWithoutWarnings();
    assertThat(result)
        .generatedSourceFile("demo.DocServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requirePermission(\"doc:delete\")");
    assertThat(result)
        .generatedSourceFile("demo.DocServiceSecured")
        .contentsAsUtf8String()
        .contains("super.delete(id)");
  }

  @Test
  @DisplayName("@RequiresPermission with multiple values lowers to requireAllPermissions(...)")
  void multiPermissionGeneratesRequireAllPermissions() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.ReportService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class ReportService {",
        "    @RequiresPermission({\"report:read\", \"report:export\"})",
        "    public void export() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.ReportServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requireAllPermissions(\"report:read\", \"report:export\")");
  }

  @Test
  @DisplayName("@RequiresAnyPermission generates requireAnyPermission(...)")
  void anyPermissionGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.AnyService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresAnyPermission;",
        "",
        "@Secured",
        "public class AnyService {",
        "    @RequiresAnyPermission({\"a\", \"b\"})",
        "    public void touch() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.AnyServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requireAnyPermission(\"a\", \"b\")");
  }

  @Test
  @DisplayName("@RequiresAllPermissions generates requireAllPermissions(...)")
  void allPermissionsGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.AllService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresAllPermissions;",
        "",
        "@Secured",
        "public class AllService {",
        "    @RequiresAllPermissions({\"x\", \"y\"})",
        "    public void touch() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.AllServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requireAllPermissions(\"x\", \"y\")");
  }

  @Test
  @DisplayName("@RequiresRole with single role lowers to requireRole(role)")
  void singleRoleGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.AdminService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class AdminService {",
        "    @RequiresRole(\"ADMIN\")",
        "    public void cleanup() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.AdminServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requireRole(\"ADMIN\")");
  }

  @Test
  @DisplayName("@RequiresRole with multiple roles lowers to requireAnyRole(...)")
  void multiRoleGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.MultiRoleService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class MultiRoleService {",
        "    @RequiresRole({\"ADMIN\", \"EDITOR\"})",
        "    public void edit() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.MultiRoleServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requireAnyRole(\"ADMIN\", \"EDITOR\")");
  }

  @Test
  @DisplayName("@RequiresPolicy generates requirePolicy(name)")
  void policyGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.PolicyService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresPolicy;",
        "",
        "@Secured",
        "public class PolicyService {",
        "    @RequiresPolicy(\"doc.owner-or-admin\")",
        "    public void edit() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.PolicyServiceSecured")
        .contentsAsUtf8String()
        .contains("JSentinelEnforcer.requirePolicy(\"doc.owner-or-admin\")");
  }

  @Test
  @DisplayName("Unannotated method in @Secured class generates pure super-call")
  void unannotatedMethodHasNoEnforcerCall() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.MixedService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class MixedService {",
        "    @RequiresPermission(\"a\")",
        "    public void guarded() {}",
        "",
        "    public String unguarded(final String input) { return input; }",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    String generated = generatedFileContent(result, "demo.MixedServiceSecured");

    if (generated.contains("super.unguarded(input)")) {
      // expected delegate call present
    } else {
      throw new AssertionError("unguarded() must still delegate; got: " + generated);
    }
    // the unguarded method must NOT contain an enforcer call …
    int guardedIdx = generated.indexOf("super.guarded()");
    int unguardedIdx = generated.indexOf("super.unguarded(input)");
    String unguardedSlice = generated.substring(guardedIdx, unguardedIdx);
    if (unguardedSlice.lastIndexOf("JSentinelEnforcer.")
        > unguardedSlice.lastIndexOf("super.guarded()")) {
      throw new AssertionError(
          "enforcer call leaked into the unguarded() method; full source:\n" + generated);
    }
  }

  @Test
  @DisplayName("Class-level annotation guards otherwise-unannotated methods")
  void classLevelAnnotationGuardsMethods() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.ClassGuardedService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "@RequiresRole(\"ADMIN\")",
        "public class ClassGuardedService {",
        "    public void one() {}",
        "    public void two() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    String generated = generatedFileContent(result, "demo.ClassGuardedServiceSecured");
    long requireRoleCalls = generated.lines()
        .filter(l -> l.contains("JSentinelEnforcer.requireRole(\"ADMIN\")"))
        .count();
    if (requireRoleCalls != 2) {
      throw new AssertionError("expected 2 requireRole calls (one per method), got "
          + requireRoleCalls + "; source:\n" + generated);
    }
  }

  @Test
  @DisplayName("Method-level annotation wins over class-level")
  void methodLevelOverridesClassLevel() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.HybridService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "@RequiresRole(\"USER\")",
        "public class HybridService {",
        "    @RequiresPermission(\"admin:special\")",
        "    public void elevated() {}",
        "    public void ordinary() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    String generated = generatedFileContent(result, "demo.HybridServiceSecured");
    // elevated() picks permission, ordinary() falls back to class-level role
    if (!generated.contains("requirePermission(\"admin:special\")")) {
      throw new AssertionError("expected method-level requirePermission; got:\n" + generated);
    }
    if (!generated.contains("requireRole(\"USER\")")) {
      throw new AssertionError("expected class-level requireRole fallback; got:\n" + generated);
    }
  }

  // ── negative cases (delegated to proxybuilder) ───────────────────

  @Test
  @DisplayName("A method with two security annotations fails with processing/multiple-security-annotations (R031)")
  void multipleSecurityAnnotationsOnMethodRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DoubleAnnotatedService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class DoubleAnnotatedService {",
        "    @RequiresPermission(\"doc:delete\")",
        "    @RequiresRole(\"ADMIN\")",
        "    public void delete() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/multiple-security-annotations");
  }

  @Test
  @DisplayName("A class with two security annotations fails with processing/multiple-security-annotations (R031)")
  void multipleSecurityAnnotationsOnClassRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DoubleAnnotatedClass",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;",
        "import com.svenruppert.jsentinel.authorization.annotations.RequiresAnyPermission;",
        "",
        "@Secured",
        "@RequiresRole(\"ADMIN\")",
        "@RequiresAnyPermission({\"a\", \"b\"})",
        "public class DoubleAnnotatedClass {",
        "    public void op() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/multiple-security-annotations");
  }

  @Test
  @DisplayName("@Secured on a final class produces a compile error")
  void finalClassRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.FinalService",
        "package demo;",
        "import com.svenruppert.jsentinel.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public final class FinalService {",
        "    public void op() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static String generatedFileContent(Compilation compilation, String qualifiedName) {
    return compilation.generatedSourceFiles().stream()
        .filter(jfo -> jfo.getName().endsWith(qualifiedName.replace('.', '/') + ".java"))
        .findFirst()
        .map(jfo -> {
          try (var reader = jfo.openReader(true)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[1024];
            int n;
            while ((n = reader.read(buf)) > 0) {
              sb.append(buf, 0, n);
            }
            return sb.toString();
          } catch (Exception e) {
            throw new AssertionError("could not read " + qualifiedName, e);
          }
        })
        .orElseThrow(() -> new AssertionError(
            "no generated source file matched " + qualifiedName
                + "; generated: " + compilation.generatedSourceFiles()));
  }
}
