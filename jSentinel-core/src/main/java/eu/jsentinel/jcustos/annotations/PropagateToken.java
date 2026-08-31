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
package eu.jsentinel.jcustos.annotations;

import eu.jsentinel.jcustos.authorization.annotations.JSentinelAnnotation;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.credential.propagation.PropagateTokenAdvisor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker for client interfaces / methods whose outbound HTTP call must
 * carry a {@link PropagateTokenAdvisor}-resolved header (typically the
 * Bearer token of the current subject, optionally exchanged via
 * {@code TokenExchangeStrategy}).
 *
 * <p>Meta-annotated with
 * {@link JSentinelAnnotation @JSentinelAnnotation(PropagateTokenAdvisor.class)}
 * so the V00.70 {@code JSentinelAnnotationScanner} discovers it
 * through the same cache as {@code @RequiresRole} /
 * {@code @RequiresPermission}.
 *
 * <p>Resolution at runtime (V00.74 Prompts 008 + 011 + 013):
 * <ul>
 *   <li>Method-level annotation overrides class-level. Identical to
 *       the {@code @RequiresRole} resolution rule.</li>
 *   <li>{@link #strategy()} is the lookup key against the named
 *       strategies registered in the bootstrap
 *       {@code .propagation(p -> p.strategy(name, ...))}.</li>
 *   <li>{@link #audience()} flows into {@code OutboundCall} so strategy
 *       implementations (in particular {@code TokenExchangeStrategy})
 *       know which downstream audience to mint a token for.</li>
 *   <li>{@link #header()} overrides the strategy's default header name
 *       (e.g. {@code "X-Service-Token"} for a custom flow).</li>
 *   <li>{@link #service()} is a logical service name used in
 *       diagnostics / audit metadata.</li>
 * </ul>
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi("V00.74 token propagation; stable promotion staged for V00.76")
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@JSentinelAnnotation(PropagateTokenAdvisor.class)
public @interface PropagateToken {

  /** Lookup key against the named strategies. Default {@code "pass-through"}. */
  String strategy() default "pass-through";

  /** Declared audience for the downstream call. Default empty. */
  String audience() default "";

  /** Override of the strategy's default header name. Default empty (use strategy default). */
  String header() default "";

  /** Logical service name for diagnostics / audit metadata. Default empty. */
  String service() default "";
}
