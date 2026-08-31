package eu.jsentinel.jcustos.demo.skill.standalone.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JSentinelVersionKey;
import eu.jsentinel.jcustos.session.JSentinelVersionStore;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.User;

import java.util.Optional;

/**
 * Increments the per-subject {@code JSentinelVersion} so any session
 * captured before the bump drifts on the next request and the
 * affected user is rerouted to {@code MyLoginView} by
 * {@code JSentinelVersionEnforcerListener}.
 *
 * <p>Call sites: every role-mutating operation in
 * {@code AdminRolesView} — {@code assignRole}, {@code revokeRole},
 * {@code deleteUser}. The bumper itself is a no-op when the SPI is
 * absent — so the call sites can stay unconditional.
 */
public final class VersionBumper implements HasLogger {

  private VersionBumper() {
  }

  /**
   * Increments the per-subject version for {@code user}. Returns the
   * post-increment value, or empty when the
   * {@link JSentinelVersionStore} SPI is not registered (e.g. the
   * hardening skill was reverted).
   */
  public static Optional<Long> bump(User user) {
    if (user == null) {
      return Optional.empty();
    }
    Optional<JSentinelVersionStore> storeOpt =
        JSentinelServiceResolver.findJSentinelVersionStore();
    if (storeOpt.isEmpty()) {
      return Optional.empty();
    }
    JSentinelVersionKey key = new JSentinelVersionKey(
        TenantId.DEFAULT, SubjectId.of(user.id().toString()));
    return Optional.of(storeOpt.get().increment(key).value());
  }
}
