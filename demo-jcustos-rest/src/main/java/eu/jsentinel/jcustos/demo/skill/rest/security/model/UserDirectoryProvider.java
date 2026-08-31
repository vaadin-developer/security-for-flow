package eu.jsentinel.jcustos.demo.skill.rest.security.model;

import java.util.Objects;

/**
 * Static holder for the {@link UserDirectory} singleton.
 *
 * <p>Needed because consumers loaded via {@link java.util.ServiceLoader}
 * — {@code MyAuthenticationService},
 * {@code MyAuthorizationService} — cannot receive the
 * directory through constructor injection. Tests can replace the
 * directory via {@link #setDirectory(UserDirectory)} and reset with
 * {@link #reset()}.
 */
public final class UserDirectoryProvider {

  private static volatile UserDirectory directory = new InMemoryUserDirectory();

  private UserDirectoryProvider() {
  }

  public static UserDirectory directory() {
    return directory;
  }

  /** Test seam — install a custom directory. */
  public static void setDirectory(UserDirectory replacement) {
    directory = Objects.requireNonNull(replacement, "replacement");
  }

  /** Test seam — restore the default in-memory directory. */
  public static void reset() {
    directory = new InMemoryUserDirectory();
  }
}
