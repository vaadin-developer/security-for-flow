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
package eu.jsentinel.jcustos.authorization.navigation;

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Vaadin-free context for access evaluation.
 *
 * @param subject      authenticated subject, if available
 * @param resourceType adapter-neutral resource type
 * @param resourceName adapter-neutral resource name
 * @param operation    requested operation
 * @param attributes   adapter-provided contextual attributes
 */
public record AccessContext(
    Optional<JSentinelSubject> subject,
    String resourceType,
    String resourceName,
    String operation,
    Map<String, Object> attributes
) {

  /**
   * Creates an access context with defensive copies.
   *
   * @param subject      authenticated subject, if available
   * @param resourceType adapter-neutral resource type
   * @param resourceName adapter-neutral resource name
   * @param operation    requested operation
   * @param attributes   adapter-provided contextual attributes
   */
  public AccessContext {
    subject = subject == null ? Optional.empty() : subject;
    resourceType = requireNotBlank(resourceType, "resourceType");
    resourceName = requireNotBlank(resourceName, "resourceName");
    operation = requireNotBlank(operation, "operation");
    attributes = Map.copyOf(requireNonNull(attributes, "attributes must not be null"));
  }

  /**
   * Compatibility constructor for existing Vaadin navigation code.
   *
   * @param path       requested path
   * @param target     navigation target class
   * @param attributes adapter-provided contextual attributes
   */
  public AccessContext(String path, Class<?> target, Map<String, Object> attributes) {
    this(
        Optional.empty(),
        "vaadin-view",
        requireNonNull(target, "target must not be null").getSimpleName(),
        "navigate",
        vaadinAttributes(path, target, attributes));
  }

  /**
   * Compatibility accessor for the former path component.
   *
   * @return requested path, if known
   */
  public String path() {
    Object path = attributes.get("path");
    return path == null ? resourceName : String.valueOf(path);
  }

  /**
   * Compatibility accessor for the former target component.
   *
   * @return target class, if known
   */
  public Class<?> target() {
    Object target = attributes.get("target");
    return target instanceof Class<?> targetClass ? targetClass : null;
  }

  private static String requireNotBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }

  private static Map<String, Object> vaadinAttributes(
      String path,
      Class<?> target,
      Map<String, Object> attributes) {
    Map<String, Object> result = new LinkedHashMap<>(
        attributes == null ? Map.of() : attributes);
    result.put("path", requireNonNull(path, "path must not be null"));
    result.put("target", requireNonNull(target, "target must not be null"));
    return result;
  }
}
