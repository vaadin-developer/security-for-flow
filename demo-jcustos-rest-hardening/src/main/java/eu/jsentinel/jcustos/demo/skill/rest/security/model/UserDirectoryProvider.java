package eu.jsentinel.jcustos.demo.skill.rest.security.model;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Replacement for the layer-1 {@code jcustos-vaadin} provider.
 *
 * <p>Default wires an {@link EclipseStoreUserDirectoryPersistence}
 * under {@code ./data/jcustos-rest-persistence/users}, then injects it into a
 * {@link PersistentUserDirectory}. The Eclipse-Store-backed
 * persistence runs in its own {@code EmbeddedStorageManager}
 * independent of the framework storage.
 *
 * <p>Test seam: {@link #setDirectory(UserDirectory)} swaps the
 * singleton — pair with {@link InMemoryUserDirectoryPersistence} for
 * stateless tests.
 */
public final class UserDirectoryProvider {

  public static final Path USERS_STORAGE_DIR = Path.of("./data/jcustos-rest-persistence/users");

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
        new EclipseStoreUserDirectoryPersistence(USERS_STORAGE_DIR);
    Runtime.getRuntime().addShutdownHook(new Thread(persistence::close,
        "user-directory-persistence-shutdown"));
    return new PersistentUserDirectory(
        persistence,
        JCustosServiceResolver.passwordHashingService());
  }
}
