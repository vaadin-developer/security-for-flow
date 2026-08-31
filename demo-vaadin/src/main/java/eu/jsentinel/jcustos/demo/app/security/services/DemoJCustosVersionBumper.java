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
package eu.jsentinel.jcustos.demo.app.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;

import java.util.Optional;

/**
 * Bumps the SPI-registered {@link JCustosVersionStore} for a given
 * {@link MyUser} so existing sessions for that user drift on the
 * next request. Used by the admin role-management UI: revoking or
 * granting a role increments the security version, which the
 * {@code JCustosVersionEnforcerListener} sees on the affected
 * user's next navigation and reroutes to the login view.
 * <p>
 * No-op when {@link JCustosServiceResolver#findJCustosVersionStore()}
 * returns empty, so the demo still runs cleanly when the SPI is
 * not registered.
 */
public final class DemoJCustosVersionBumper implements HasLogger {

  private DemoJCustosVersionBumper() {
  }

  /**
   * Increments the per-subject security version for {@code user}.
   * Returns the post-increment value, or empty when no store is
   * registered.
   */
  public static Optional<Long> bump(MyUser user) {
    if (user == null) {
      return Optional.empty();
    }
    Optional<JCustosVersionStore> storeOpt =
        JCustosServiceResolver.findJCustosVersionStore();
    if (storeOpt.isEmpty()) {
      return Optional.empty();
    }
    JCustosVersionKey key = new JCustosVersionKey(
        TenantId.DEFAULT, SubjectId.of(user.id().toString()));
    return Optional.of(storeOpt.get().increment(key).value());
  }
}
