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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

/**
 * Maps an application's typed subject {@code U} to the
 * adapter-neutral {@link SubjectId} (and optionally to a
 * {@link TenantId}).
 * <p>
 * The framework's adapter code (Vaadin login flow, REST filters,
 * audit emit-sites) sometimes has a {@code U} value and needs to
 * derive its {@link SubjectId} — which is application-specific
 * (e.g. {@code User#username()}, {@code Account#id()}). This SPI
 * is the single hook: applications register an implementation via
 * {@code META-INF/services/eu.jsentinel.jcustos.authorization.api.SubjectIdResolver}
 * (or programmatically via
 * {@link JCustosServiceResolver#setSubjectIdResolver}) so the
 * framework can construct {@link SubjectId} from {@code U}
 * without guessing.
 *
 * <p>Used by {@code security-vaadin}'s {@code LoginView} after a
 * successful login to capture the {@code JCustosVersion}
 * snapshot into {@code VaadinJCustosVersionContext}. Without a
 * resolver, the capture is silently skipped — the
 * {@code JCustosVersionEnforcerListener} simply finds no snapshot
 * and lets every request through.
 *
 * @param <U> application user type
 */
@FunctionalInterface
public interface SubjectIdResolver<U> {

  /**
   * Returns the {@link SubjectId} for {@code subject}.
   *
   * @param subject typed user; never {@code null}
   * @return stable subject id, never {@code null}
   */
  SubjectId resolve(U subject);

  /**
   * Returns the {@link TenantId} for {@code subject}. Defaults to
   * {@link TenantId#DEFAULT} so single-tenant applications don't
   * have to override.
   *
   * @param subject typed user; never {@code null}
   * @return tenant scope, never {@code null}
   */
  default TenantId tenantFor(U subject) {
    return TenantId.DEFAULT;
  }
}
