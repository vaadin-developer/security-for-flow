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
package com.svenruppert.vaadin.security.authorization.api.operations;

import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;

import java.util.List;
import java.util.Objects;

/**
 * Filters {@link SecuredOperationDescriptor}s against a {@link JSentinelSubject}.
 * <p>
 * An operation is visible when the subject has all required roles AND all
 * required permissions. Empty role/permission sets are treated as
 * "authenticated-only" and pass for any non-{@code null} subject.
 */
public final class OperationVisibilityService {

  private final SecuredOperationRegistry registry;

  public OperationVisibilityService(SecuredOperationRegistry registry) {
    this.registry = Objects.requireNonNull(registry, "registry");
  }

  public List<SecuredOperationDescriptor> visibleFor(JSentinelSubject subject) {
    if (subject == null) return List.of();
    return registry.all().stream()
        .filter(op -> isAllowed(subject, op))
        .toList();
  }

  static boolean isAllowed(JSentinelSubject subject, SecuredOperationDescriptor op) {
    if (!subject.roles().containsAll(op.requiredRoles())) return false;
    return subject.permissions().containsAll(op.requiredPermissions());
  }
}
