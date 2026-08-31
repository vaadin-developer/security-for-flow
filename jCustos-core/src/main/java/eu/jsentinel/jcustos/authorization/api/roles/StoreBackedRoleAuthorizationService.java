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

import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * {@link AuthorizationService} that looks roles up in a
 * {@link RoleAssignmentStore}.
 * <p>
 * Generic over the application's user type {@code U}; constructors
 * take resolver functions that map a user to its {@link SubjectId}
 * and tenant. Single-tenant applications use the two-arg
 * constructor and every lookup runs against
 * {@link TenantId#DEFAULT}.
 *
 * <p>Permissions stay at the {@link AuthorizationService} default
 * (empty) — applications that want store-backed permissions wrap
 * this service with a {@code PermissionAuthorizationService} that
 * additionally consults a
 * {@link eu.jsentinel.jcustos.authorization.api.permissions.RolePermissionMapping}.
 *
 * @param <U> application user type
 */
@ExperimentalJCustosApi
public final class StoreBackedRoleAuthorizationService<U> implements AuthorizationService<U> {

  private final RoleAssignmentStore store;
  private final Function<U, SubjectId> subjectIdResolver;
  private final Function<U, TenantId> tenantResolver;

  /**
   * Single-tenant constructor. Every lookup runs against
   * {@link TenantId#DEFAULT}.
   *
   * @param store             role-assignment store; non-null
   * @param subjectIdResolver maps a user to its {@code SubjectId};
   *                          non-null
   */
  public StoreBackedRoleAuthorizationService(RoleAssignmentStore store,
                                             Function<U, SubjectId> subjectIdResolver) {
    this(store, subjectIdResolver, u -> TenantId.DEFAULT);
  }

  /**
   * Multi-tenant constructor.
   *
   * @param store             role-assignment store; non-null
   * @param subjectIdResolver maps a user to its {@code SubjectId};
   *                          non-null
   * @param tenantResolver    maps a user to its {@code TenantId};
   *                          non-null; may return {@code null}, which
   *                          becomes {@link TenantId#DEFAULT}
   */
  public StoreBackedRoleAuthorizationService(RoleAssignmentStore store,
                                             Function<U, SubjectId> subjectIdResolver,
                                             Function<U, TenantId> tenantResolver) {
    this.store = requireNonNull(store, "store must not be null");
    this.subjectIdResolver = requireNonNull(subjectIdResolver,
        "subjectIdResolver must not be null");
    this.tenantResolver = requireNonNull(tenantResolver,
        "tenantResolver must not be null");
  }

  @Override
  public HasRoles rolesFor(U subject) {
    requireNonNull(subject, "subject must not be null");
    SubjectId subjectId = requireNonNull(
        subjectIdResolver.apply(subject),
        "subjectIdResolver must not return null");
    TenantId tenant = tenantResolver.apply(subject);
    Set<RoleName> roles = store.findRoles(
        new RoleAssignmentKey(tenant == null ? TenantId.DEFAULT : tenant, subjectId));
    List<RoleName> copy = List.copyOf(roles);
    return () -> copy;
  }
}
