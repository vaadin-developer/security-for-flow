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
package com.svenruppert.jsentinel.autoservice.processor;

import org.junit.jupiter.api.Test;

import javax.tools.Diagnostic;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JSentinelAutoServiceProcessorTest {

  @Test
  void noAnnotation_noResourcesGenerated() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Plain", """
        package com.example;
        public class Plain {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);

    assertTrue(r.success, diagSummary(r));
    assertFalse(r.generatedResources.keySet().stream()
            .anyMatch(p -> p.startsWith("META-INF/services/")),
        "no service files expected; got " + r.generatedResources.keySet());
  }

  @Test
  void singleSpi_writesServiceFile() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Api", """
        package com.example;
        public interface Api {}
        """);
    sources.put("com.example.ApiImpl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(Api.class)
        public final class ApiImpl implements Api {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertTrue(r.success, diagSummary(r));

    String content = r.resourceAsString("META-INF/services/com.example.Api");
    assertNotNull(content, "expected META-INF/services/com.example.Api");
    assertTrue(content.startsWith(JSentinelAutoServiceProcessor.MARKER),
        "marker comment must be first line, got: " + content);
    assertTrue(content.contains("com.example.ApiImpl"), content);
  }

  @Test
  void multiSpi_writesBothServiceFiles() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.ApiA", """
        package com.example;
        public interface ApiA {}
        """);
    sources.put("com.example.ApiB", """
        package com.example;
        public interface ApiB {}
        """);
    sources.put("com.example.Both", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService({ApiA.class, ApiB.class})
        public final class Both implements ApiA, ApiB {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertTrue(r.success, diagSummary(r));

    assertNotNull(r.generatedResources.get("META-INF/services/com.example.ApiA"));
    assertNotNull(r.generatedResources.get("META-INF/services/com.example.ApiB"));
    assertTrue(r.resourceAsString("META-INF/services/com.example.ApiA").contains("com.example.Both"));
    assertTrue(r.resourceAsString("META-INF/services/com.example.ApiB").contains("com.example.Both"));
  }

  @Test
  void notAssignableToSpi_failsCompilation() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Api", """
        package com.example;
        public interface Api {}
        """);
    sources.put("com.example.NotAnImpl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(Api.class)
        public final class NotAnImpl {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertFalse(r.success, "expected compilation failure for non-assignable SPI");
    assertTrue(r.diagnostics.stream()
            .anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR
                && d.getMessage(null).contains("autoservice/not-assignable")),
        "expected autoservice/not-assignable error, got: " + diagSummary(r));
  }

  @Test
  void abstractClass_failsCompilation() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Api", """
        package com.example;
        public interface Api {}
        """);
    sources.put("com.example.AbstractImpl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(Api.class)
        public abstract class AbstractImpl implements Api {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertFalse(r.success);
    assertTrue(r.diagnostics.stream()
            .anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR
                && d.getMessage(null).contains("autoservice/abstract")));
  }

  @Test
  void missingNoArgConstructor_failsCompilation() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Api", """
        package com.example;
        public interface Api {}
        """);
    sources.put("com.example.NoNoArg", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(Api.class)
        public final class NoNoArg implements Api {
          public NoNoArg(String required) {}
        }
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertFalse(r.success);
    assertTrue(r.diagnostics.stream()
            .anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR
                && d.getMessage(null).contains("autoservice/missing-no-arg-ctor")));
  }

  @Test
  void writtenEntriesAreSortedDeterministically() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Api", """
        package com.example;
        public interface Api {}
        """);
    sources.put("com.example.ZImpl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(Api.class)
        public final class ZImpl implements Api {}
        """);
    sources.put("com.example.AImpl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(Api.class)
        public final class AImpl implements Api {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertTrue(r.success);

    String content = r.resourceAsString("META-INF/services/com.example.Api");
    int aPos = content.indexOf("com.example.AImpl");
    int zPos = content.indexOf("com.example.ZImpl");
    assertTrue(aPos > 0 && zPos > 0, content);
    assertTrue(aPos < zPos, "AImpl should be sorted before ZImpl: " + content);
  }

  private static String diagSummary(InMemoryCompiler.Result r) {
    StringBuilder sb = new StringBuilder();
    sb.append("success=").append(r.success).append("\nDiagnostics:");
    for (Diagnostic<?> d : r.diagnostics) {
      sb.append("\n  ").append(d.getKind()).append(" ").append(d.getMessage(null));
    }
    return sb.toString();
  }

  @Test
  void noopWhenNoAnnotationsPresent_compilationStillSucceeds() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.A", "package com.example; public class A {}");
    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertTrue(r.success, diagSummary(r));
    assertEquals(0, r.generatedResources.keySet().stream()
        .filter(p -> p.startsWith("META-INF/services/"))
        .count());
  }

  // ── V00.74.20 P016 mutation-lift: error-path coverage ──────────────────

  /**
   * Annotating a class with a non-public SPI must fail compilation
   * with the {@code autoservice/non-public-spi} diagnostic. The
   * existing happy-path tests never trigger the
   * {@code Messager.printMessage(...)} call inside
   * {@code addSpi(...)} for this branch, so the mutator that drops
   * the {@code error(...)} call survives. Hitting the branch here
   * pins that the diagnostic is emitted and compilation fails.
   */
  @Test
  void nonPublicSpi_failsWithDiagnostic() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.PackagePrivateApi", """
        package com.example;
        interface PackagePrivateApi {}
        """);
    sources.put("com.example.Impl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(PackagePrivateApi.class)
        public final class Impl implements PackagePrivateApi {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertFalse(r.success,
        "compilation must fail when the declared SPI is package-private: " + diagSummary(r));
    boolean spiNotPublic = r.diagnostics.stream()
        .anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR
            && d.getMessage(null).contains("autoservice/non-public-spi"));
    assertTrue(spiNotPublic,
        "expected autoservice/non-public-spi ERROR: " + diagSummary(r));
  }

  /**
   * A {@code @JSentinelAutoService} declared as a single-class
   * annotation (not the {@code {SpiA.class, SpiB.class}} array form)
   * exercises the {@code raw instanceof TypeMirror} else-branch in
   * {@code collectSpis(...)} — the existing tests in this class only
   * use the array form. Without this test the
   * NegateConditionalsMutator on the {@code instanceof TypeMirror}
   * branch survives.
   *
   * Note: javac normalises {@code @JSentinelAutoService(Api.class)}
   * to a single-element AnnotationValue list at the AST level, so
   * exercising the strict single-value path requires an annotation
   * source that uses the {@code value = …} explicit form.
   */
  @Test
  void singleSpiExplicitValue_pathExercisesSingleTypeMirrorBranch() throws IOException {
    Map<String, String> sources = new LinkedHashMap<>();
    sources.put("com.example.Api", """
        package com.example;
        public interface Api {}
        """);
    sources.put("com.example.Impl", """
        package com.example;
        import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
        @JSentinelAutoService(value = Api.class)
        public final class Impl implements Api {}
        """);

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);
    assertTrue(r.success, diagSummary(r));
    String content = r.resourceAsString("META-INF/services/com.example.Api");
    assertNotNull(content);
    assertTrue(content.contains("com.example.Impl"), content);
  }
}
