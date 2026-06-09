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
package com.svenruppert.vaadin.security.authorization.api;

import java.lang.annotation.*;

/**
 * Marks a type or method as part of the experimental security API.
 * <p>
 * Experimental APIs may change in incompatible ways or be removed in future
 * releases without a deprecation period. The role-based access API is the
 * stable path for production use.
 * <p>
 * Currently applies to the permission-based access API:
 * <ul>
 *   <li>{@code PermissionBasedAccessEvaluator}</li>
 *   <li>{@code PermissionName}</li>
 *   <li>{@code HasPermissions}</li>
 * </ul>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
public @interface ExperimentalJSentinelApi {

  /**
   * Description of the experimental nature.
   *
   * @return the description
   */
  String value() default "This API is experimental and may change without notice.";
}
