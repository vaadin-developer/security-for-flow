package eu.jsentinel.jcustos.dx.rest.handlers;

import java.util.stream.Stream;

/**
 * Reports the REST handlers an application exposes, so the bootstrap can tell
 * at startup whether any of them would fall through deny-by-default.
 *
 * <p>Vaadin gets this for free: its router knows every route. REST has no such
 * registry — handlers are dispatched by hand-written routing, so the framework
 * cannot enumerate them. Until now that made the deny-by-default diagnostic
 * Vaadin-only, and a REST application learned about an unprotected handler when
 * the first request hit it. This interface closes that gap by letting the
 * application state what it exposes.
 *
 * <p>Names are plain strings rather than {@code Class} or {@code Method}
 * objects: a finding only has to be readable, and strings keep this module free
 * of any dependency on the consumer's handler types.
 *
 * @since 00.82.00
 */
@FunctionalInterface
public interface RestHandlerDiscovery {

  /**
   * Names of handlers that carry no security annotation and are not marked
   * {@code @PublicRoute} — every one of them is denied at runtime once
   * deny-by-default is on, which is a fault to fix, not a state to run in.
   *
   * <p>Implementations must drain the stream before returning it. A lazy stream
   * that throws while the bootstrap consumes it fails the boot far from its
   * cause.
   *
   * @return handler names lacking a security constraint, never {@code null}
   */
  Stream<String> discoverUnannotatedHandlerNames();

  /**
   * Whether the handler set could be determined at all.
   *
   * <p>Returning {@code false} is not the same as returning an empty stream:
   * empty means "checked, nothing unprotected", false means "could not check".
   * The bootstrap reports the difference, so a discovery that silently fails
   * cannot masquerade as a clean result.
   *
   * @return {@code true} when the enumeration is meaningful
   */
  default boolean handlersAvailable() {
    return true;
  }
}
