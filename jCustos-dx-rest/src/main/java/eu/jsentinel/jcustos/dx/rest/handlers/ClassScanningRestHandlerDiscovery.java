package eu.jsentinel.jcustos.dx.rest.handlers;

import static java.util.Objects.requireNonNull;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.impl.JCustosAnnotationScanner;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * Discovers unprotected handlers by scanning the handler classes an application
 * names, so a REST application gets the same startup check Vaadin gets from its
 * router.
 *
 * <p>Pass the classes whose methods serve requests:
 *
 * <pre>{@code
 * RestSecurity.bootstrap()
 *     .discoverHandlers(new ClassScanningRestHandlerDiscovery(DocumentHandlers.class, AdminHandlers.class))
 *     .install();
 * }</pre>
 *
 * <p>A method counts as protected when it carries a security annotation, when
 * its declaring class does, or when either is marked {@link PublicRoute} — the
 * same three ways {@code RestAuthorizationFilter} accepts at runtime, so the
 * startup verdict matches what a request would meet.
 *
 * <p>What this cannot see is a handler you never pass in. The check is only as
 * complete as the list, which is the price of REST having no registry to
 * enumerate.
 *
 * @since 00.82.00
 */
public final class ClassScanningRestHandlerDiscovery implements RestHandlerDiscovery {

  private final List<Class<?>> handlerClasses;
  private final JCustosAnnotationScanner scanner = new JCustosAnnotationScanner();

  /**
   * @param handlerClasses classes whose non-static methods serve REST requests
   */
  public ClassScanningRestHandlerDiscovery(Class<?>... handlerClasses) {
    requireNonNull(handlerClasses, "handlerClasses must not be null");
    this.handlerClasses = List.copyOf(Arrays.asList(handlerClasses));
  }

  @Override
  public Stream<String> discoverUnannotatedHandlerNames() {
    List<String> unprotected = new ArrayList<>();
    for (Class<?> handlerClass : handlerClasses) {
      if (isProtected(handlerClass)) {
        continue;
      }
      for (Method method : handlerClass.getDeclaredMethods()) {
        if (method.isSynthetic() || method.isBridge() || Modifier.isStatic(method.getModifiers())) {
          continue;
        }
        if (!Modifier.isPublic(method.getModifiers())) {
          continue;
        }
        if (!isProtected(method)) {
          unprotected.add(handlerClass.getName() + "#" + method.getName());
        }
      }
    }
    // Drained here on purpose: a stream that throws while the bootstrap reads it
    // would fail the boot far from its cause.
    return unprotected.stream();
  }

  @Override
  public boolean handlersAvailable() {
    return !handlerClasses.isEmpty();
  }

  private boolean isProtected(java.lang.reflect.AnnotatedElement element) {
    if (element.isAnnotationPresent(PublicRoute.class)) {
      return true;
    }
    try {
      return scanner.scan(element).isPresent();
    } catch (RuntimeException tooManyAnnotations) {
      // More than one security annotation is a configuration error the scanner
      // reports elsewhere. Counting it as protected keeps this check from
      // claiming the handler is unguarded, which it demonstrably is not.
      return true;
    }
  }
}
