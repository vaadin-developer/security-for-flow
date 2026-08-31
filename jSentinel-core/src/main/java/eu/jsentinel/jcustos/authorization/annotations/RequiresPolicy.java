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
import eu.jsentinel.jcustos.policy.impl.RequiresPolicyEvaluator;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

/**
 * Requires the named {@code Policy} (registered with the resolved
 * {@code PolicyRegistry}) to {@code Allow} the current request.
 *
 * <p>A single annotation carries a single policy name. Combining
 * algorithms (any-of / all-of) will be added later via a separate
 * annotation to keep this contract stable.
 */
@ExperimentalJSentinelApi
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({TYPE, METHOD})
@JSentinelAnnotation(RequiresPolicyEvaluator.class)
public @interface RequiresPolicy {

  /**
   * Name of the policy registered with the {@code PolicyRegistry}.
   *
   * @return policy name
   */
  String value();
}
