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
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.TypeSpec;
import com.svenruppert.proxybuilder.proxy.generated.BasicStaticProxyAnnotationProcessor;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import com.svenruppert.vaadin.security.authorization.annotations.Secured;

import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.tools.JavaFileObject;
import java.io.IOException;
import java.io.Writer;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Generates a {@code <Type>Secured} wrapper subclass for each
 * {@link Secured @Secured}-annotated concrete class. The wrapper
 * inherits from the original, overrides every public, non-final,
 * non-static method, and inserts a {@link SecurityEnforcer}
 * pre-check ahead of the {@code super.<method>(...)} delegate when the
 * method (or the class) carries one of the method-security annotations.
 *
 * <p>Annotation mapping:
 * <ul>
 *   <li>{@link RequiresPermission} (1 value)  →
 *       {@link SecurityEnforcer#requirePermission(String)}</li>
 *   <li>{@link RequiresPermission} (n values) →
 *       {@link SecurityEnforcer#requireAllPermissions(String...)}</li>
 *   <li>{@link RequiresAllPermissions} →
 *       {@link SecurityEnforcer#requireAllPermissions(String...)}</li>
 *   <li>{@link RequiresAnyPermission} →
 *       {@link SecurityEnforcer#requireAnyPermission(String...)}</li>
 *   <li>{@link RequiresRole} (1 value)  →
 *       {@link SecurityEnforcer#requireRole(String)}</li>
 *   <li>{@link RequiresRole} (n values) →
 *       {@link SecurityEnforcer#requireAnyRole(String...)}</li>
 *   <li>{@link RequiresPolicy} →
 *       {@link SecurityEnforcer#requirePolicy(String)}</li>
 * </ul>
 *
 * <p>Method-level annotations take precedence over class-level
 * annotations; the first match wins (one enforcer call per generated
 * method).
 *
 * <p>All {@code final}/{@code private}/{@code static} diagnostics for
 * methods or classes carrying security annotations are emitted by the
 * proxybuilder base processor (see audit notes in
 * {@code Anforderungen-proxybuilder-modernisierung.md}, P1/9–13). This
 * processor only contributes the body translation.
 */
public final class SecuredAnnotationProcessor
    extends BasicStaticProxyAnnotationProcessor<Secured> {

  private static final ClassName ENFORCER = ClassName.get(
      "com.svenruppert.vaadin.security.authorization.api", "SecurityEnforcer");

  /** Creates the processor. Loaded via {@code META-INF/services}. */
  public SecuredAnnotationProcessor() {
  }

  @Override
  public Class<Secured> responsibleFor() {
    return Secured.class;
  }

  @Override
  protected void addClassLevelSpecs(TypeElement typeElement, RoundEnvironment roundEnv) {
    // SecurityEnforcer is a static facade — no instance field or
    // builder method is added to the generated wrapper.
  }

  @Override
  protected CodeBlock defineMethodImplementation(ExecutableElement methodElement,
                                                 String methodName,
                                                 TypeElement typeElementTargetClass) {
    CodeBlock.Builder body = CodeBlock.builder();

    if (!emitEnforcerCall(body, methodElement)) {
      emitEnforcerCall(body, typeElementTargetClass);
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

  /**
   * Overrides the proxybuilder writer to (a) {@code close()} the
   * {@link Writer} after the JavaPoet output is flushed and
   * (b) strip the {@code @GeneratedByProxyBuilder} marker annotation
   * from the generated class.
   *
   * <p>(a) is needed because the base
   * implementation only calls {@code flush()} which leaves
   * {@code com.google.testing.compile}'s in-memory file manager
   * unable to read the generated content. Real javac filers tolerate
   * the missing {@code close()} because the file object is finalized
   * after the round; the in-memory manager is stricter.
   *
   * <p>(b) is needed so consumers of {@code security-processor} do
   * not have to put {@code proxybuilder} on their compile classpath
   * just to satisfy a source-retention marker. The annotation has no
   * runtime effect (it is {@link java.lang.annotation.RetentionPolicy#SOURCE}),
   * so dropping it leaves the generated class semantically unchanged.
   */
  @Override
  protected Optional<TypeSpec> writeDefinedClass(String pkgName,
                                                 TypeSpec.Builder typeSpecBuilder) {
    typeSpecBuilder.annotations.removeIf(spec ->
        "com.svenruppert.proxybuilder.GeneratedByProxyBuilder".equals(spec.type.toString()));
    TypeSpec typeSpec = typeSpecBuilder.build();
    JavaFile javaFile = JavaFile.builder(pkgName, typeSpec)
        .skipJavaLangImports(true)
        .build();
    String fqn = pkgName.isEmpty() ? typeSpec.name : pkgName + "." + typeSpec.name;
    try {
      JavaFileObject jfo = filer.createSourceFile(fqn);
      try (Writer writer = jfo.openWriter()) {
        javaFile.writeTo(writer);
      }
    } catch (IOException e) {
      messager.printMessage(javax.tools.Diagnostic.Kind.ERROR,
          "Could not write " + fqn + ": " + e.getMessage());
    }
    return Optional.of(typeSpec);
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
}
