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
package com.svenruppert.jsentinel.authorization.api.operations;

import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Adapter-neutral description of a secured operation.
 * <p>
 * The triple {@code (resourceType, resourceName, operation)} can later be
 * fed into an {@code AccessContext}. {@code attributes} is a small
 * extension slot for adapter-specific metadata (e.g. HTTP method + path
 * for REST endpoints, view class name for Vaadin routes).
 *
 * @param id                  stable, unique operation id
 * @param label               short user-facing label
 * @param description         optional longer description
 * @param resourceType        resource category (e.g. {@code rest-endpoint},
 *                            {@code vaadin-view})
 * @param resourceName        resource name (e.g. {@code /api/documents/{id}})
 * @param operation           operation verb (e.g. {@code delete},
 *                            {@code navigate})
 * @param requiredRoles       required roles; empty means no role gate
 * @param requiredPermissions required permissions; empty means no permission gate
 * @param attributes          adapter-specific metadata
 */
public record SecuredOperationDescriptor(
    String id,
    String label,
    String description,
    String resourceType,
    String resourceName,
    String operation,
    Set<RoleName> requiredRoles,
    Set<PermissionName> requiredPermissions,
    Map<String, Object> attributes
) {

  public SecuredOperationDescriptor {
    requireNonBlank(id, "id");
    requireNonBlank(label, "label");
    requireNonBlank(resourceType, "resourceType");
    requireNonBlank(resourceName, "resourceName");
    requireNonBlank(operation, "operation");
    description = description == null ? "" : description;
    requiredRoles = Set.copyOf(Objects.requireNonNull(requiredRoles, "requiredRoles"));
    requiredPermissions = Set.copyOf(Objects.requireNonNull(requiredPermissions, "requiredPermissions"));
    attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
  }

  public boolean isAuthenticatedOnly() {
    return requiredRoles.isEmpty() && requiredPermissions.isEmpty();
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
