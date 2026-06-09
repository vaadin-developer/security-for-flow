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
package com.svenruppert.vaadin.security.authorization.annotations;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.permissions.RequiresAllPermissionsEvaluator;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

/**
 * Requires the current subject to hold <strong>all</strong> listed
 * permissions (AND-semantics).
 *
 * <p>Semantically equivalent to
 * {@link RequiresPermission}{@code (String[])} with multiple values,
 * but explicit about the AND-semantics — useful when readers should
 * not have to remember whether {@code @RequiresPermission({"a","b"})}
 * means "a AND b" or "a OR b". When the rule should be OR, use
 * {@link RequiresAnyPermission} instead.
 */
@ExperimentalJSentinelApi
@Retention(RetentionPolicy.RUNTIME)
@Target({TYPE, METHOD})
@JSentinelAnnotation(RequiresAllPermissionsEvaluator.class)
public @interface RequiresAllPermissions {

  /**
   * Required permission names. Every entry must be held by the
   * authenticated subject for access to be granted.
   *
   * @return permission names; must contain at least one entry
   */
  String[] value();
}
