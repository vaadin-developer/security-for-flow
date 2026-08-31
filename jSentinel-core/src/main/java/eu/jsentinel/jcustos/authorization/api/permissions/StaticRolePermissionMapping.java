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
package eu.jsentinel.jcustos.authorization.api.permissions;

import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Static, immutable {@link RolePermissionMapping}. Useful when the role-to
 * -permission mapping comes from configuration or code rather than a
 * persistent store.
 */
public final class StaticRolePermissionMapping implements RolePermissionMapping {

  private final Map<RoleName, Set<PermissionName>> mapping;

  public StaticRolePermissionMapping(Map<RoleName, Set<PermissionName>> mapping) {
    Objects.requireNonNull(mapping, "mapping");
    Map<RoleName, Set<PermissionName>> copy = new java.util.LinkedHashMap<>();
    for (Map.Entry<RoleName, Set<PermissionName>> entry : mapping.entrySet()) {
      copy.put(entry.getKey(), Set.copyOf(entry.getValue()));
    }
    this.mapping = Map.copyOf(copy);
  }

  @Override
  public Set<PermissionName> permissionsFor(RoleName role) {
    return mapping.getOrDefault(role, Set.of());
  }

  /** Convenient builder-style starter. */
  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private final Map<RoleName, Set<PermissionName>> mapping = new java.util.LinkedHashMap<>();

    public Builder put(RoleName role, Set<PermissionName> permissions) {
      mapping.put(role, Set.copyOf(permissions));
      return this;
    }

    public Builder put(String role, String... permissions) {
      Set<PermissionName> perms = new java.util.LinkedHashSet<>();
      for (String p : permissions) perms.add(new PermissionName(p));
      mapping.put(new RoleName(role), Set.copyOf(perms));
      return this;
    }

    public StaticRolePermissionMapping build() {
      return new StaticRolePermissionMapping(mapping);
    }
  }
}
