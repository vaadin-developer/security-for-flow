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
package com.svenruppert.vaadin.security.rest.openapi;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;

import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Result of running
 * {@link OpenApiJSentinelMetadataGenerator#generate} on a handler
 * class. Carries the class-level and per-method
 * {@link JSentinelRequirement}s the generator extracted.
 * <p>
 * Apps building an OpenAPI document combine
 * {@link #classLevel()} with each entry of {@link #methods()} for
 * the corresponding operation — the runtime evaluator AND-s them,
 * so the OpenAPI exporter should reflect that.
 *
 * @param handlerClassName  fully qualified handler class name; non-blank
 * @param classLevel        class-level requirements (apply to every
 *                          method on the class); non-null, immutable
 * @param methods           per-method requirements keyed on method
 *                          name; non-null, immutable, contains no
 *                          {@code null} keys or values
 */
@ExperimentalJSentinelApi
public record HandlerJSentinelMetadata(
    String handlerClassName,
    List<JSentinelRequirement> classLevel,
    Map<String, List<JSentinelRequirement>> methods
) {

  /** Validates the components and freezes the collections. */
  public HandlerJSentinelMetadata {
    if (handlerClassName == null || handlerClassName.isBlank()) {
      throw new IllegalArgumentException("handlerClassName must not be blank");
    }
    requireNonNull(classLevel, "classLevel must not be null");
    requireNonNull(methods, "methods must not be null");
    classLevel = List.copyOf(classLevel);
    // Defensive copy of each list inside the map
    var copy = new java.util.LinkedHashMap<String, List<JSentinelRequirement>>(methods.size());
    for (var entry : methods.entrySet()) {
      String name = entry.getKey();
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException("methods keys must not be blank");
      }
      List<JSentinelRequirement> reqs = entry.getValue();
      requireNonNull(reqs, "methods values must not be null");
      copy.put(name, List.copyOf(reqs));
    }
    methods = Map.copyOf(copy);
  }

  /**
   * @return {@code true} when there is no class-level requirement
   *         <em>and</em> no method-level requirement
   */
  public boolean isEmpty() {
    return classLevel.isEmpty() && methods.isEmpty();
  }
}
