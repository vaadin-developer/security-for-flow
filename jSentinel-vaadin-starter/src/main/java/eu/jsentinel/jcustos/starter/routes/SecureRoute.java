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
package eu.jsentinel.jcustos.starter.routes;

import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Convenience annotation combining role, permission and policy checks
 * on a Vaadin route.
 * <p>
 * Semantics (most-restrictive-wins):
 * <ul>
 *   <li>{@code roles}: any-of — at least one role must be present.</li>
 *   <li>{@code permissions}: all-of — every permission must be present.</li>
 *   <li>{@code policy}: single policy that must evaluate as
 *       {@code Granted}.</li>
 *   <li>If multiple of the three are set, the route is granted only when
 *       <em>all</em> underlying decisions are {@code Granted}. The
 *       combination precedence for non-Granted outcomes is:
 *       {@code Unauthenticated} &gt; {@code Forbidden} &gt;
 *       {@code StepUpRequired} &gt; {@code Granted}.</li>
 * </ul>
 *
 * @since 00.72.00
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@JCustosAnnotation(SecureRouteEvaluator.class)
public @interface SecureRoute {

  String[] roles() default {};

  String[] permissions() default {};

  String policy() default "";
}
