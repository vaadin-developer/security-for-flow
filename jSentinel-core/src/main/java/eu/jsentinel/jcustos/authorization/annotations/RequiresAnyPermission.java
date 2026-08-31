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
package eu.jsentinel.jcustos.authorization.annotations;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.permissions.RequiresAnyPermissionEvaluator;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

/**
 * Requires the current subject to hold <strong>at least one</strong>
 * of the listed permissions (OR-semantics).
 *
 * <p>Contrast with {@link RequiresPermission}, which requires
 * <strong>all</strong> listed permissions. Pick {@code @RequiresAnyPermission}
 * when the admission rule is "subject has read- OR write-access on this
 * resource", and {@link RequiresAllPermissions} when the rule is
 * "subject has both X and Y" — the latter being explicit about the
 * AND-semantics that {@code @RequiresPermission} also offers.
 */
@ExperimentalJSentinelApi
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({TYPE, METHOD})
@JSentinelAnnotation(RequiresAnyPermissionEvaluator.class)
public @interface RequiresAnyPermission {

  /**
   * Required permission names. At least one must be held by the
   * authenticated subject for access to be granted.
   *
   * @return permission names; must contain at least one entry
   */
  String[] value();
}
