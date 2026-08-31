package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.JCustosStorageProvider;

import java.util.Objects;

/**
 * Replacement for the layer-1 {@code jsentinel-standalone} provider.
 *
 * <p>Default wires an {@link EclipseStoreUserDirectoryPersistence}
 * around the app-side storage manager exposed by
 * {@link JCustosStorageProvider#app()} and injects it into a
 * {@link PersistentUserDirectory}. The user-directory storage shares
 * the {@code JCustosStoragePair}'s lifecycle — no separate manager,
 * no separate shutdown hook (V00.74.20+).
 *
 * <p>Test seam: {@link #setDirectory(UserDirectory)} swaps the
 * singleton — pair with {@link InMemoryUserDirectoryPersistence} for
 * stateless tests.
 */
public final class UserDirectoryProvider {

  private static volatile UserDirectory directory = buildDefault();

  private UserDirectoryProvider() {
  }

  public static UserDirectory directory() {
    return directory;
  }

  /** Test seam — install a custom directory. */
  public static void setDirectory(UserDirectory replacement) {
    directory = Objects.requireNonNull(replacement, "replacement");
  }

  /** Test seam — restore the default Eclipse-Store-backed directory. */
  public static void reset() {
    directory = buildDefault();
  }

  private static UserDirectory buildDefault() {
    UserDirectoryPersistence persistence =
        new EclipseStoreUserDirectoryPersistence(JCustosStorageProvider.app());
    // No shutdown hook here — JCustosStorageProvider owns the
    // single shutdown hook that closes the pair.
    return new PersistentUserDirectory(
        persistence,
        JCustosServiceResolver.passwordHashingService());
  }
}
