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
package com.svenruppert.vaadin.security.policy.api;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;

/**
 * Named, single-shot authorisation rule.
 * <p>
 * A {@code Policy} is built once via {@link #named(String)} + a fluent
 * {@link PolicyBuilder}, registered with a {@code PolicyRegistry}, and
 * then evaluated against a {@link PolicyContext} on every protected
 * access. Built-in implementations follow this semantics:
 * <ol>
 *   <li>If any {@code denyIf}-predicate matches → {@code Denied}.</li>
 *   <li>Otherwise, if any {@code allowIf}/{@code orIf}-predicate matches
 *       → {@code Allowed}.</li>
 *   <li>Otherwise → {@code Denied} with the configured default reason.</li>
 * </ol>
 *
 * <p>The sealed hierarchy keeps the public surface to two types: this
 * interface and the {@link PolicyBuilder}. Implementations stay
 * package-private.
 */
@ExperimentalJSentinelApi
public sealed interface Policy permits NamedPolicy {

  /**
   * Stable, unique name of this policy. Used as the lookup key in
   * {@code PolicyRegistry} and as the value of
   * {@code @RequiresPolicy("...")}.
   *
   * @return policy name
   */
  String name();

  /**
   * Evaluates this policy against the given context.
   *
   * @param context policy context; must not be {@code null}
   * @return decision
   */
  PolicyDecision evaluate(PolicyContext context);

  /**
   * Starts a fluent builder for a policy with the given name.
   *
   * @param name unique, non-blank policy name
   * @return builder
   */
  static PolicyBuilder named(String name) {
    return new PolicyBuilder(name);
  }
}
