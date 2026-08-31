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
package eu.jsentinel.jcustos.demo.restclient.security;

import eu.jsentinel.jcustos.authorization.annotations.JSentinelAnnotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.TYPE;

/**
 * Project-specific view-protection annotation (Stil B in the concept doc):
 * a thin custom restriction backed by an evaluator owned by this demo.
 * Coexists with the generic {@code @RequiresRole} / {@code @RequiresPermission}
 * from {@code security-core} so reviewers can compare both pathways.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(TYPE)
@JSentinelAnnotation(ProjectRoleAccessEvaluator.class)
public @interface VisibleForRoles {

  ProjectRole[] value();
}
