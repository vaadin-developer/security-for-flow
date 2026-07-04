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
package com.svenruppert.jsentinel.authorization.annotations;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

/**
 * Explicit opt-out marker (JS-SEC-024 / CWE-862): the annotated Vaadin
 * {@code @Route} class or REST handler class/method is intentionally public and
 * must stay reachable even when deny-by-default is enabled via
 * {@code JSentinelServiceResolver.setDenyByDefault(true)}.
 *
 * <p>Unlike the {@code @Requires*} annotations this marker carries no
 * {@link JSentinelAnnotation} meta-binding, so {@code JSentinelAnnotationScanner}
 * ignores it (it never resolves an evaluator). It is consulted only by the
 * deny-by-default guard via {@link java.lang.reflect.AnnotatedElement#isAnnotationPresent}.
 * Retention is {@link RetentionPolicy#RUNTIME} so it is reflectively checkable at
 * navigation / request time. Place it on the same element you hand to the scanner
 * (a Vaadin route class, or the REST handler method/class).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({TYPE, METHOD})
public @interface PublicRoute {
}
