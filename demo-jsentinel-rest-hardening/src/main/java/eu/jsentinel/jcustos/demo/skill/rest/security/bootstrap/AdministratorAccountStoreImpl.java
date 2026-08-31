package eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.bootstrap.AdministratorAccountStore;
import eu.jsentinel.jcustos.bootstrap.NewAdministrator;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;

import java.util.EnumSet;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Adapter from {@link AdministratorAccountStore} (the bootstrap-flow
 * SPI) to the application's {@link UserDirectory}.
 *
 * <p>{@link NewAdministrator#passwordHash()} is already hashed by the
 * bootstrap service — this adapter calls
 * {@link UserDirectory#registerWithHashedPassword(String, String, Object)}
 * to bypass re-hashing.
 *
 * <p>Logs at {@code INFO} before and after the directory write and at
 * {@code ERROR} on failure — <em>before</em> rethrowing — because the
 * jCustos-Core {@code InitialAdminBootstrapService.createInitialAdmin}
 * catches blanket {@code RuntimeException} and converts to
 * {@code InternalError("could not persist administrator")} with no
 * cause attached. Without this local logging the operator sees only
 * the generic error message and can't diagnose persistence failures.
 */
public final class AdministratorAccountStoreImpl
    implements AdministratorAccountStore, HasLogger {

  private final UserDirectory directory;
  private final AtomicLong idSequence = new AtomicLong(1000);

  public AdministratorAccountStoreImpl(UserDirectory directory) {
    this.directory = Objects.requireNonNull(directory, "directory");
  }

  @Override
  public boolean hasAnyAdministrator() {
    return directory.hasAnyAdministrator();
  }

  @Override
  public void createAdministrator(NewAdministrator newAdministrator) {
    String displayName = newAdministrator.displayName() == null
        || newAdministrator.displayName().isBlank()
        ? newAdministrator.username()
        : newAdministrator.displayName();
    User user = new User(
        idSequence.getAndIncrement(),
        displayName,
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
    logger().info("Persisting initial administrator: username='{}', id={}, roles={}",
        newAdministrator.username(), user.id(), user.roles());
    try {
      directory.registerWithHashedPassword(
          newAdministrator.username(),
          newAdministrator.passwordHash(),
          user);
      logger().info("Initial administrator '{}' (id={}) committed to {}",
          newAdministrator.username(), user.id(),
          directory.getClass().getSimpleName());
    } catch (RuntimeException failure) {
      logger().error("Failed to persist initial administrator '{}' (id={}): {}",
          newAdministrator.username(), user.id(), failure.toString(), failure);
      throw failure;
    }
  }
}
