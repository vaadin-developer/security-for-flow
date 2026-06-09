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
package com.svenruppert.vaadin.security.processor;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.svenruppert.proxybuilder.proxy.generated.BasicStaticProxyAnnotationProcessor;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import com.svenruppert.vaadin.security.authorization.annotations.Secured;

import javax.annotation.processing.FilerException;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import javax.tools.FileObject;
import javax.tools.StandardLocation;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Generates a {@code <Type>Secured} wrapper subclass for each
 * {@link Secured @Secured}-annotated concrete class. The wrapper
 * inherits from the original, overrides every public, non-final,
 * non-static method, and inserts a
 * {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer JSentinelEnforcer}
 * pre-check ahead of the {@code super.<method>(...)} delegate when the
 * method (or the class) carries one of the method-security annotations.
 *
 * <p>Annotation mapping:
 * <ul>
 *   <li>{@link RequiresPermission} (1 value)  →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requirePermission(String)}</li>
 *   <li>{@link RequiresPermission} (n values) →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requireAllPermissions(String...)}</li>
 *   <li>{@link RequiresAllPermissions} →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requireAllPermissions(String...)}</li>
 *   <li>{@link RequiresAnyPermission} →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requireAnyPermission(String...)}</li>
 *   <li>{@link RequiresRole} (1 value)  →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requireRole(String)}</li>
 *   <li>{@link RequiresRole} (n values) →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requireAnyRole(String...)}</li>
 *   <li>{@link RequiresPolicy} →
 *       {@link com.svenruppert.vaadin.security.authorization.api.JSentinelEnforcer#requirePolicy(String)}</li>
 * </ul>
 *
 * <p>Method-level annotations take precedence over class-level
 * annotations; the first match wins (one enforcer call per generated
 * method).
 *
 * <p>All {@code final}/{@code private}/{@code static} diagnostics for
 * methods or classes carrying security annotations are emitted by the
 * underlying {@code com.svenruppert:proxybuilder:00.11.00} base
 * processor — this processor only contributes the body translation.
 *
 * <p>The generated class carries
 * {@code @GeneratedByProxyBuilder(...)} and
 * {@code @DelegatesTo(...)} from the {@code proxybuilder-annotations}
 * module; consumers of {@code security-processor} pull that module as
 * a regular compile dependency so the markers resolve in their own
 * compile classpath.
 */
public final class SecuredAnnotationProcessor
    extends BasicStaticProxyAnnotationProcessor<Secured> {

  private static final ClassName ENFORCER = ClassName.get(
      "com.svenruppert.vaadin.security.authorization.api", "JSentinelEnforcer");

  // V00.73: wrapper-index writer state. Must stay in sync with the
  // package-private com.svenruppert.vaadin.security.dx.diagnostics.WrapperIndexFormat
  // class in security-dx — that module's classes aren't visible here,
  // so the literals are duplicated and the reader matches by value.
  private static final String INDEX_RESOURCE_PATH =
      "META-INF/security-for-flow/generated-wrappers.idx";
  private static final String INDEX_MARKER_COMMENT =
      "# generated by security-for-flow security-processor";
  private static final String INDEX_FIELD_SEPARATOR = ":";
  private static final String INDEX_METHOD_SEPARATOR = ",";
  private static final String INDEX_PROCESSOR_ID = "proxybuilder";
  private static final String INDEX_PROXYBUILDER_VERSION = "00.11.00";

  /**
   * Per-source-FQN list of guarded method names collected during this
   * compilation. Iteration order is alphabetical (TreeMap) so the
   * written file is deterministic across runs.
   */
  private final Map<String, List<String>> indexBySource = new TreeMap<>();

  /** The source FQN currently being processed; set by {@link #addClassLevelSpecs}. */
  private String currentSourceFqn;

  /** Creates the processor. Loaded via {@code META-INF/services}. */
  public SecuredAnnotationProcessor() {
  }

  @Override
  public Class<Secured> responsibleFor() {
    return Secured.class;
  }

  @Override
  public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
    final boolean claimed = super.process(annotations, roundEnv);
    if (roundEnv.processingOver()) {
      writeIndex();
    }
    return claimed;
  }

  @Override
  protected void addClassLevelSpecs(TypeElement typeElement, RoundEnvironment roundEnv) {
    // JSentinelEnforcer is a static facade — no instance field or
    // builder method is added to the generated wrapper. The hook is
    // used to capture the FQN of the class being processed so that
    // index entries can be attributed to it later.
    currentSourceFqn = typeElement.getQualifiedName().toString();
    indexBySource.computeIfAbsent(currentSourceFqn, k -> new ArrayList<>());
  }

  @Override
  protected CodeBlock defineMethodImplementation(ExecutableElement methodElement,
                                                 String methodName,
                                                 TypeElement typeElementTargetClass) {
    CodeBlock.Builder body = CodeBlock.builder();

    boolean guarded = emitEnforcerCall(body, methodElement);
    if (!guarded) {
      guarded = emitEnforcerCall(body, typeElementTargetClass);
    }
    if (guarded && currentSourceFqn != null) {
      List<String> methods = indexBySource.get(currentSourceFqn);
      if (methods != null && !methods.contains(methodName)) {
        methods.add(methodName);
      }
    }

    String paramList = methodElement.getParameters().stream()
        .map(p -> p.getSimpleName().toString())
        .collect(Collectors.joining(", "));

    TypeMirror returnType = methodElement.getReturnType();
    if (returnType.getKind() == TypeKind.VOID) {
      body.addStatement("super.$L($L)", methodName, paramList);
    } else {
      body.addStatement("return super.$L($L)", methodName, paramList);
    }

    return body.build();
  }

  /**
   * Appends a single enforcer call for the first matching annotation
   * found on {@code element}.
   *
   * @return {@code true} when an enforcer call was appended,
   * {@code false} when {@code element} carries none of the recognised
   * method-security annotations
   */
  private boolean emitEnforcerCall(CodeBlock.Builder body, Element element) {
    RequiresPermission rp = element.getAnnotation(RequiresPermission.class);
    if (rp != null) {
      if (rp.value().length == 1) {
        body.addStatement("$T.requirePermission($S)", ENFORCER, rp.value()[0]);
      } else {
        emitVarargsCall(body, "requireAllPermissions", rp.value());
      }
      return true;
    }

    RequiresAllPermissions rap = element.getAnnotation(RequiresAllPermissions.class);
    if (rap != null) {
      emitVarargsCall(body, "requireAllPermissions", rap.value());
      return true;
    }

    RequiresAnyPermission ranyp = element.getAnnotation(RequiresAnyPermission.class);
    if (ranyp != null) {
      emitVarargsCall(body, "requireAnyPermission", ranyp.value());
      return true;
    }

    RequiresRole rr = element.getAnnotation(RequiresRole.class);
    if (rr != null) {
      if (rr.value().length == 1) {
        body.addStatement("$T.requireRole($S)", ENFORCER, rr.value()[0]);
      } else {
        emitVarargsCall(body, "requireAnyRole", rr.value());
      }
      return true;
    }

    RequiresPolicy rpol = element.getAnnotation(RequiresPolicy.class);
    if (rpol != null) {
      body.addStatement("$T.requirePolicy($S)", ENFORCER, rpol.value());
      return true;
    }

    return false;
  }

  private static void emitVarargsCall(CodeBlock.Builder body,
                                      String enforcerMethod,
                                      String[] values) {
    StringBuilder format = new StringBuilder("$T.").append(enforcerMethod).append("(");
    Object[] args = new Object[values.length + 1];
    args[0] = ENFORCER;
    for (int i = 0; i < values.length; i++) {
      if (i > 0) {
        format.append(", ");
      }
      format.append("$S");
      args[i + 1] = values[i];
    }
    format.append(")");
    body.addStatement(format.toString(), args);
  }

  /**
   * Writes the merged wrapper index in {@code processingOver()}. Reads
   * the pre-existing file once, merges the entries collected in this
   * compilation (replacing prior entries for the same source FQN), and
   * writes a deterministic, alphabetically sorted file. Failures are
   * {@link Diagnostic.Kind#WARNING} — wrapper generation success is
   * never affected by index-write problems.
   *
   * <p>Implementation notes (matching Konzept §11.3):
   * <ul>
   *   <li>{@link javax.annotation.processing.Filer#getResource} may throw
   *       {@link IOException} or {@link UnsupportedOperationException}
   *       in some in-memory file managers; both are treated as
   *       "no prior file present".</li>
   *   <li>{@link javax.annotation.processing.Filer#createResource} may
   *       throw {@link FilerException} on re-write; the writer runs in
   *       {@code processingOver()} so it is invoked exactly once per
   *       compilation.</li>
   * </ul>
   */
  private void writeIndex() {
    Map<String, List<String>> merged = readExistingIndex();
    indexBySource.forEach(merged::put);

    if (merged.isEmpty()) {
      return;
    }

    try {
      FileObject out = filer.createResource(
          StandardLocation.CLASS_OUTPUT, "", INDEX_RESOURCE_PATH);
      try (Writer w = out.openWriter()) {
        w.write(INDEX_MARKER_COMMENT);
        w.write("\n");
        for (Map.Entry<String, List<String>> e : merged.entrySet()) {
          String sourceFqn = e.getKey();
          String generatedFqn = sourceFqn + "Secured";
          // de-dup methods while preserving insertion order
          String methods = new LinkedHashSet<>(e.getValue()).stream()
              .collect(Collectors.joining(INDEX_METHOD_SEPARATOR));
          w.write(sourceFqn);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(generatedFqn);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(INDEX_PROCESSOR_ID);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(INDEX_PROXYBUILDER_VERSION);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(methods);
          w.write("\n");
        }
      }
    } catch (FilerException fe) {
      messager.printMessage(Diagnostic.Kind.WARNING,
          "processor/index-write-failed: " + fe.getMessage());
    } catch (IOException io) {
      messager.printMessage(Diagnostic.Kind.WARNING,
          "processor/index-write-failed: " + io.getMessage());
    }
  }

  private Map<String, List<String>> readExistingIndex() {
    Map<String, List<String>> result = new TreeMap<>();
    try {
      FileObject existing = filer.getResource(
          StandardLocation.CLASS_OUTPUT, "", INDEX_RESOURCE_PATH);
      try (BufferedReader r = new BufferedReader(existing.openReader(true))) {
        String line;
        while ((line = r.readLine()) != null) {
          if (line.isBlank() || line.startsWith("#")) {
            continue;
          }
          String[] parts = line.split(INDEX_FIELD_SEPARATOR, 5);
          if (parts.length < 5) {
            continue;
          }
          List<String> methods = parts[4].isBlank()
              ? new ArrayList<>()
              : new ArrayList<>(Arrays.asList(parts[4].split(INDEX_METHOD_SEPARATOR)));
          methods.replaceAll(String::trim);
          result.put(parts[0].trim(), methods);
        }
      }
    } catch (IOException | RuntimeException ignored) {
      // No prior file (or unreadable resource in in-memory file manager)
      // → start with an empty map. RuntimeException covers
      // UnsupportedOperationException from some Filer implementations.
    }
    return result;
  }
}
