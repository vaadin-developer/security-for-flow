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
package com.svenruppert.vaadin.security.demo.standalone;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import com.svenruppert.vaadin.security.authorization.annotations.Secured;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Concrete library-member registry guarded by the framework's
 * compile-time method-security path. {@code @Secured} marks this class
 * for the {@code security-processor} annotation processor, which emits
 * a {@code MemberDirectorySecured} subclass at compile time. The
 * generated subclass overrides every public, non-final, non-static
 * method, calls the matching
 * {@code SecurityEnforcer.require…(…)} helper, and then forwards to
 * {@code super.<method>(…)}.
 *
 * <p>Counterpart to {@link LibraryService} (an interface guarded via
 * {@code SecuredProxy.wrap(...)} at runtime) — together both services
 * show the two enforcement paths the framework offers:
 *
 * <ul>
 *   <li><b>Runtime</b>: dynamic-proxy on an interface
 *       (<code>LibraryService</code>).</li>
 *   <li><b>Compile-time</b>: annotation-processor on a concrete class
 *       (<code>MemberDirectory</code>).</li>
 * </ul>
 *
 * <p>The method-security annotation set is deliberately broad so the
 * processor exercises all four lowering paths:
 *
 * <ul>
 *   <li>{@link RequiresPermission} (single value) →
 *       {@code SecurityEnforcer.requirePermission(name)}</li>
 *   <li>{@link RequiresAnyPermission} →
 *       {@code SecurityEnforcer.requireAnyPermission(...)}</li>
 *   <li>{@link RequiresAllPermissions} →
 *       {@code SecurityEnforcer.requireAllPermissions(...)}</li>
 *   <li>{@link RequiresRole} (single value) →
 *       {@code SecurityEnforcer.requireRole(role)}</li>
 * </ul>
 */
@Secured
public class MemberDirectory {

  private final Map<String, String> members = new ConcurrentHashMap<>();

  /** Creates an empty member directory. */
  public MemberDirectory() {
  }

  /**
   * Lists every registered member's name in insertion-stable order.
   *
   * @return registered member names
   */
  @RequiresPermission("member:list")
  public List<String> listMembers() {
    return List.copyOf(members.keySet());
  }

  /**
   * Registers a new member. Allowed for subjects that hold either
   * {@code member:add} (regular registration) or {@code member:invite}
   * (invitation flow).
   *
   * @param name  member display name (must be unique)
   * @param email contact email
   */
  @RequiresAnyPermission({"member:add", "member:invite"})
  public void addMember(String name, String email) {
    members.put(name, email);
  }

  /**
   * Removes a member. Requires <strong>both</strong>
   * {@code member:remove} (the destructive operation) and
   * {@code member:audit-log} (so the removal is auditable) — this is
   * the demo's AND-semantics example.
   *
   * @param name member name to remove
   */
  @RequiresAllPermissions({"member:remove", "member:audit-log"})
  public void removeMember(String name) {
    members.remove(name);
  }

  /**
   * Drops every registered member. Reserved for the {@code ADMIN}
   * role.
   */
  @RequiresRole("ADMIN")
  public void resetAll() {
    members.clear();
  }
}
