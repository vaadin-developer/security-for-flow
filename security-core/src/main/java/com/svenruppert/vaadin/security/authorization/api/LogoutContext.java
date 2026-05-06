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

import java.util.Map;
import java.util.Objects;

/**
 * Context for a single logout call. Adapter-neutral; the
 * {@link #attributes()} map carries adapter-specific data such as the
 * Vaadin {@code UI} reference, request ip, audit correlation id etc.
 *
 * @param policy     behaviour switches for the logout
 * @param attributes optional adapter-specific data
 */
public record LogoutContext(LogoutPolicy policy, Map<String, Object> attributes) {

  public LogoutContext {
    Objects.requireNonNull(policy, "policy");
    attributes = Map.copyOf(attributes == null ? Map.of() : attributes);
  }

  public static LogoutContext of(LogoutPolicy policy) {
    return new LogoutContext(policy, Map.of());
  }
}
