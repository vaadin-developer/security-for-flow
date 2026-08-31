/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.propagation.processor;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Filer;
import javax.annotation.processing.Messager;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * V00.74 compile-time wrapper generator for {@code @PropagateToken}.
 *
 * <p>For each concrete class annotated at the class level (or with any
 * annotated method), emits a {@code <Type>Propagating} subclass that
 * overrides every {@code public} non-{@code final} non-{@code static}
 * method. The override binds the
 * {@link eu.jsentinel.jcustos.credential.propagation.PropagateTokenAdvisor.Default
 * advisor}-resolved {@code HeaderValue} into
 * {@link eu.jsentinel.jcustos.credential.propagation.OutboundHeaderContext}
 * around the {@code super.method(...)} call.
 *
 * <p><strong>Concrete classes only.</strong> For interfaces, use the
 * runtime path
 * {@code PropagatingProxy.wrap} (jCustos-propagation)
 * — interfaces don't have a sensible {@code super} call shape, and the
 * JDK Dynamic Proxy already covers that use case.
 *
 * <p>{@code final} / {@code private} / {@code static} methods annotated
 * {@code @PropagateToken} produce a compile error.
 *
 * @since 00.74.00
 */
@SupportedAnnotationTypes("eu.jsentinel.jcustos.annotations.PropagateToken")
@SupportedSourceVersion(SourceVersion.RELEASE_26)
public final class PropagateTokenProcessor extends AbstractProcessor {

  private Filer filer;
  private Messager messager;
  private Types types;

  /** Required by {@link javax.annotation.processing.Processor}; the compiler instantiates it. */
  public PropagateTokenProcessor() {
  }

  @Override
  public synchronized void init(ProcessingEnvironment env) {
    super.init(env);
    this.filer = env.getFiler();
    this.messager = env.getMessager();
    this.types = env.getTypeUtils();
  }

  @Override
  public boolean process(Set<? extends TypeElement> annotations,
                         RoundEnvironment roundEnv) {
    if (annotations.isEmpty() || roundEnv.processingOver()) {
      return false;
    }

    // Collect type-level targets: classes whose elements (class or
    // method) carry @PropagateToken. We always generate one wrapper
    // per enclosing class.
    Set<TypeElement> targets = new LinkedHashSet<>();
    for (TypeElement annotationType : annotations) {
      for (Element element : roundEnv.getElementsAnnotatedWith(annotationType)) {
        validate(element);
        TypeElement enclosing = enclosingType(element);
        if (enclosing != null && enclosing.getKind() == ElementKind.CLASS) {
          targets.add(enclosing);
        }
      }
    }

    for (TypeElement target : targets) {
      try {
        emit(target);
      } catch (IOException e) {
        messager.printMessage(Diagnostic.Kind.ERROR,
            "Failed to write " + target.getQualifiedName() + "Propagating: " + e.getMessage(),
            target);
      }
    }
    return true;
  }

  /**
   * Method-level validation: {@code @PropagateToken} cannot wrap
   * {@code final} / {@code private} / {@code static} methods.
   */
  private void validate(Element element) {
    if (element.getKind() == ElementKind.METHOD) {
      Set<Modifier> mods = element.getModifiers();
      if (mods.contains(Modifier.FINAL)) {
        messager.printMessage(Diagnostic.Kind.ERROR,
            "@PropagateToken cannot wrap final methods", element);
      }
      if (mods.contains(Modifier.PRIVATE)) {
        messager.printMessage(Diagnostic.Kind.ERROR,
            "@PropagateToken cannot wrap private methods", element);
      }
      if (mods.contains(Modifier.STATIC)) {
        messager.printMessage(Diagnostic.Kind.ERROR,
            "@PropagateToken cannot wrap static methods", element);
      }
    }
  }

  private static TypeElement enclosingType(Element element) {
    if (element instanceof TypeElement t) return t;
    Element e = element.getEnclosingElement();
    while (e != null && !(e instanceof TypeElement)) {
      e = e.getEnclosingElement();
    }
    return (TypeElement) e;
  }

  private void emit(TypeElement target) throws IOException {
    if (target.getKind() != ElementKind.CLASS) {
      messager.printMessage(Diagnostic.Kind.NOTE,
          "@PropagateToken on " + target.getQualifiedName() + " — interfaces use "
              + "PropagatingProxy.wrap(...) at runtime; no source emitted", target);
      return;
    }
    String packageName = packageOf(target);
    String simpleName = target.getSimpleName().toString();
    String generated = simpleName + "Propagating";
    String generatedFqn = packageName.isEmpty() ? generated : packageName + "." + generated;
    String sourceFqn = target.getQualifiedName().toString();
    List<MethodSpec> methods = collectMethods(target);

    JavaFileObject file = filer.createSourceFile(generatedFqn, target);
    try (Writer w = file.openWriter()) {
      writeSource(w, packageName, simpleName, generated, sourceFqn, methods);
    }
  }

  private static String packageOf(TypeElement type) {
    Element enclosing = type.getEnclosingElement();
    while (enclosing != null && enclosing.getKind() != ElementKind.PACKAGE) {
      enclosing = enclosing.getEnclosingElement();
    }
    return enclosing == null ? "" : enclosing.toString();
  }

  /**
   * @return public non-final non-static methods we need to override.
   */
  private List<MethodSpec> collectMethods(TypeElement target) {
    List<MethodSpec> methods = new ArrayList<>();
    for (Element member : target.getEnclosedElements()) {
      if (member.getKind() != ElementKind.METHOD) continue;
      Set<Modifier> mods = member.getModifiers();
      if (!mods.contains(Modifier.PUBLIC)) continue;
      if (mods.contains(Modifier.FINAL) || mods.contains(Modifier.STATIC)) continue;
      ExecutableElement m = (ExecutableElement) member;
      methods.add(MethodSpec.from(m, types));
    }
    return methods;
  }

  private void writeSource(Writer w, String packageName, String sourceSimpleName,
                            String generatedSimpleName, String sourceFqn,
                            List<MethodSpec> methods) throws IOException {
    if (!packageName.isEmpty()) {
      w.write("package " + packageName + ";\n\n");
    }
    w.write("import eu.jsentinel.jcustos.annotations.PropagateToken;\n");
    w.write("import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;\n");
    w.write("import eu.jsentinel.jcustos.credential.propagation.HeaderValue;\n");
    w.write("import eu.jsentinel.jcustos.credential.propagation.OutboundCall;\n");
    w.write("import eu.jsentinel.jcustos.credential.propagation.OutboundHeaderContext;\n");
    w.write("import eu.jsentinel.jcustos.credential.propagation.PropagateTokenAdvisor;\n");
    w.write("import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;\n\n");
    w.write("import java.util.Map;\n");
    w.write("import java.util.Optional;\n\n");
    w.write("/** Generated by jCustos-propagation-processor. */\n");
    w.write("public class " + generatedSimpleName + " extends " + sourceSimpleName + " {\n\n");
    for (MethodSpec spec : methods) {
      w.write(spec.render(sourceSimpleName));
    }
    w.write("}\n");
  }

  /** Minimal data carrier for one to-be-overridden method. */
  private record MethodSpec(String typeParams,
                            String name,
                            String returnType,
                            boolean voidReturn,
                            List<Param> params,
                            List<String> thrown) {

    static MethodSpec from(ExecutableElement m, Types types) {
      // R17 (V00.76.10): render the method's own type parameters (with bounds)
      // so a generic method like `<T extends Foo> void m(T t)` is overridden with
      // a matching signature — the old generator dropped them and emitted an
      // uncompilable `T.class`, breaking the consuming build.
      String typeParams = "";
      if (!m.getTypeParameters().isEmpty()) {
        typeParams = m.getTypeParameters().stream().map(tp -> {
          String tpName = tp.getSimpleName().toString();
          String bounds = tp.getBounds().stream()
              .map(TypeMirror::toString)
              .filter(b -> !b.equals("java.lang.Object"))
              .collect(Collectors.joining(" & "));
          return bounds.isEmpty() ? tpName : tpName + " extends " + bounds;
        }).collect(Collectors.joining(", ", "<", "> "));
      }

      boolean varargs = m.isVarArgs();
      List<? extends VariableElement> ps = m.getParameters();
      List<Param> params = new ArrayList<>();
      for (int i = 0; i < ps.size(); i++) {
        VariableElement p = ps.get(i);
        // The signature uses the parameter's declared (generic) type; the
        // reflective getMethod(...) lookup uses the ERASURE so a type variable
        // resolves to its bound (java.lang.Object by default) — a valid `.class`
        // literal that matches the erased method signature reflection sees.
        String declaredType = p.asType().toString();
        String erased = types.erasure(p.asType()).toString();
        boolean lastVararg = varargs && i == ps.size() - 1;
        params.add(new Param(declaredType, erased, p.getSimpleName().toString(), lastVararg));
      }

      List<String> thrown = m.getThrownTypes().stream()
          .map(TypeMirror::toString)
          .toList();
      TypeMirror ret = m.getReturnType();
      boolean voidReturn = ret.toString().equals("void");
      String returnType = ret.toString();
      return new MethodSpec(typeParams, m.getSimpleName().toString(),
          returnType, voidReturn, params, thrown);
    }

    String render(String sourceSimpleName) {
      StringBuilder sb = new StringBuilder();
      // Signature: render the last parameter as varargs (`T... name`) when the
      // overridden method is varargs, so the override stays varargs-compatible.
      String paramSig = params.stream().map(p -> {
        if (p.vararg()) {
          String base = p.declaredType().endsWith("[]")
              ? p.declaredType().substring(0, p.declaredType().length() - 2)
              : p.declaredType();
          return base + "... " + p.name();
        }
        return p.declaredType() + " " + p.name();
      }).collect(Collectors.joining(", "));
      String argList = params.stream()
          .map(Param::name)
          .collect(Collectors.joining(", "));
      String throwsClause = thrown.isEmpty() ? ""
          : " throws " + String.join(", ", thrown);
      sb.append("  @Override\n")
        .append("  public ").append(typeParams).append(returnType).append(' ').append(name)
        .append('(').append(paramSig).append(')').append(throwsClause).append(" {\n");
      // The reflective method lookup obtains the @PropagateToken instance the
      // advisor needs (strategy()/header()/audience()). The try/catch is emitted
      // inline — the prior version post-processed the body with a fragile
      // String.replace (R18). sourceSimpleName + name are Java identifiers, which
      // cannot contain quote/backslash, so emitting them as literals is safe; the
      // erased `.class` literals are framework/JDK type names, never user strings.
      sb.append("    PropagateToken __ann;\n");
      sb.append("    try {\n");
      sb.append("      __ann = ").append(sourceSimpleName)
        .append(".class.getMethod(\"").append(name).append('"');
      for (Param p : params) {
        sb.append(", ").append(p.erasedClass()).append(".class");
      }
      sb.append(").getAnnotation(PropagateToken.class);\n");
      sb.append("    } catch (NoSuchMethodException __e) {\n");
      sb.append("      throw new RuntimeException(__e);\n");
      sb.append("    }\n");
      sb.append("    if (__ann == null) __ann = ")
        .append(sourceSimpleName).append(".class.getAnnotation(PropagateToken.class);\n");
      sb.append("    if (__ann != null) {\n");
      sb.append("      TokenCredentialStore __store = JCustosServiceResolver.tokenCredentialStore();\n");
      sb.append("      OutboundCall __call = new OutboundCall(\"")
        .append(sourceSimpleName).append("\", \"").append(name)
        .append("\", __ann.audience(), Map.of());\n");
      sb.append("      Optional<HeaderValue> __h = PropagateTokenAdvisor.Default.INSTANCE\n")
        .append("          .adviseFor(__ann, __call, __store);\n");
      sb.append("      if (__h.isPresent()) {\n");
      sb.append("        OutboundHeaderContext.bind(__h.get());\n");
      sb.append("        try {\n");
      sb.append("          ").append(voidReturn ? "" : "return ")
        .append("super.").append(name).append('(').append(argList).append(");\n");
      sb.append(voidReturn ? "          return;\n" : "");
      sb.append("        } finally {\n");
      sb.append("          OutboundHeaderContext.clear();\n");
      sb.append("        }\n");
      sb.append("      }\n");
      sb.append("    }\n");
      sb.append("    ").append(voidReturn ? "" : "return ")
        .append("super.").append(name).append('(').append(argList).append(");\n");
      sb.append("  }\n\n");
      return sb.toString();
    }
  }

  private record Param(String declaredType, String erasedClass, String name, boolean vararg) {
  }
}
