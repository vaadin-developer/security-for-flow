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
package eu.jsentinel.jcustos.authorization.api.roles;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Immutable, programmatically-built {@link RoleHierarchy}.
 * <p>
 * Build with the fluent {@link #builder()} and {@code role(parent)
 * .inheritsFrom(child, ...)} pattern; the resulting hierarchy
 * pre-computes the transitive closure of implied roles for every
 * declared parent, so {@link #impliedRoles(RoleName)} is a
 * constant-time map lookup.
 *
 * <p>Example:
 * <pre>
 * RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
 *     .role(new RoleName("ROLE_ADMIN")).inheritsFrom(new RoleName("ROLE_EDITOR"))
 *     .role(new RoleName("ROLE_EDITOR")).inheritsFrom(new RoleName("ROLE_VIEWER"))
 *     .build();
 *
 * hierarchy.impliesRole(adminRole, viewerRole); // true (ADMIN → EDITOR → VIEWER)
 * </pre>
 *
 * <p>Cycles in the declared inheritance graph are rejected at
 * {@link Builder#build()} time.
 */
@ExperimentalJSentinelApi
public final class StaticRoleHierarchy implements RoleHierarchy {

  private final Map<RoleName, Set<RoleName>> closure;

  private StaticRoleHierarchy(Map<RoleName, Set<RoleName>> closure) {
    this.closure = closure;
  }

  /**
   * Creates a new builder.
   *
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public Set<RoleName> impliedRoles(RoleName held) {
    requireNonNull(held, "held must not be null");
    Set<RoleName> implied = closure.get(held);
    if (implied != null) {
      return implied;
    }
    // Roles that were never declared as parents still imply themselves.
    return Set.of(held);
  }

  /**
   * Fluent builder for {@link StaticRoleHierarchy}.
   */
  public static final class Builder {

    private final Map<RoleName, Set<RoleName>> directChildren = new HashMap<>();
    private RoleName currentParent;

    private Builder() {
    }

    /**
     * Selects the parent role to register children for. Subsequent
     * calls to {@link #inheritsFrom(RoleName, RoleName...)} attach
     * children to this parent. Calling {@code role(...)} multiple
     * times accumulates children across calls.
     *
     * @param parent the inheriting role
     * @return this builder
     */
    public Builder role(RoleName parent) {
      requireNonNull(parent, "parent must not be null");
      this.currentParent = parent;
      directChildren.computeIfAbsent(parent, k -> new LinkedHashSet<>());
      return this;
    }

    /**
     * Registers one or more child roles that {@code currentParent}
     * inherits from. Must be preceded by a call to
     * {@link #role(RoleName)}.
     *
     * @param first the first inherited role
     * @param rest  additional inherited roles
     * @return this builder
     */
    public Builder inheritsFrom(RoleName first, RoleName... rest) {
      if (currentParent == null) {
        throw new IllegalStateException(
            "call role(parent) before inheritsFrom(...)");
      }
      requireNonNull(first, "first must not be null");
      Set<RoleName> children = directChildren.get(currentParent);
      children.add(first);
      for (RoleName child : rest) {
        children.add(requireNonNull(child, "rest entries must not be null"));
      }
      return this;
    }

    /**
     * Builds the immutable hierarchy.
     *
     * <p>Cycle detection (R034): {@link #walk(RoleName)} runs once per declared
     * parent and throws when it reaches a child equal to that walk's own start.
     * Because {@code build()} walks <em>every</em> declared parent and every node
     * in a cycle has an outgoing edge (so is itself a declared parent), walking
     * from any cycle member reaches a back-edge to that member — therefore every
     * cycle is rejected, regardless of {@code directChildren} iteration order.
     * The guard is reachable and complete; there is no dead branch.
     *
     * @return hierarchy
     * @throws IllegalStateException if the declared inheritance graph
     *                               contains a cycle
     */
    public RoleHierarchy build() {
      Map<RoleName, Set<RoleName>> closure = new HashMap<>();
      for (RoleName parent : directChildren.keySet()) {
        closure.put(parent, Set.copyOf(walk(parent)));
      }
      return new StaticRoleHierarchy(Map.copyOf(closure));
    }

    private Set<RoleName> walk(RoleName start) {
      Set<RoleName> visited = new LinkedHashSet<>();
      visited.add(start);
      Deque<RoleName> stack = new ArrayDeque<>();
      stack.push(start);
      while (!stack.isEmpty()) {
        RoleName current = stack.pop();
        Set<RoleName> children = directChildren.getOrDefault(current, Set.of());
        for (RoleName child : children) {
          if (child.equals(start)) {
            throw new IllegalStateException(
                "Role hierarchy contains a cycle involving " + start.value());
          }
          if (visited.add(child)) {
            stack.push(child);
          }
        }
      }
      return visited;
    }
  }
}
