/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
public @interface ExperimentalSecurityApi {
  String value() default "This API is experimental and may change without notice.";
}
