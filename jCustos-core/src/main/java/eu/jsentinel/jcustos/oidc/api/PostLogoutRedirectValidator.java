package eu.jsentinel.jcustos.oidc.api;

import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Decides whether a {@code post_logout_redirect_uri} may be sent to the
 * provider (CWE-601).
 *
 * <p>The specification puts this check on the provider: it matches the URI
 * against the ones registered for the client. That is true and remains the
 * primary defence — but it is a check the relying party neither performs nor
 * observes. If the URI reaching the logout request came from the current HTTP
 * request, an attacker controls where the user lands afterwards, and the
 * relying party has handed that decision away without looking at it.
 *
 * <p>Validating here is defence in depth: cheap, local, and it turns a silent
 * dependency on someone else's configuration into an explicit statement of
 * where logout may lead.
 *
 * @since 00.82.00
 */
@FunctionalInterface
public interface PostLogoutRedirectValidator {

  /**
   * @param candidate the URI a caller wants to use, never {@code null}
   * @return {@code true} when the redirect may be requested
   */
  boolean isAllowed(URI candidate);

  /**
   * Accepts every URI — the behaviour of releases before 00.82.00, kept as the
   * default so existing callers are unaffected.
   *
   * <p>Choose this only when the provider's registered-URI check is known to be
   * strict, or when the redirect target is a constant in your own code rather
   * than something derived from a request.
   *
   * @return a validator that permits anything
   */
  static PostLogoutRedirectValidator permitAll() {
    return candidate -> true;
  }

  /**
   * Accepts only URIs whose scheme, host, port and path match one of the given
   * URIs exactly.
   *
   * <p>Comparison is exact rather than prefix-based on purpose. A prefix check
   * on {@code https://app.example.com} also accepts
   * {@code https://app.example.com.attacker.test}, which is the classic way an
   * allowlist ends up permitting the very thing it was written to stop. Query
   * strings and fragments are ignored — they carry no authority.
   *
   * @param allowed the permitted redirect targets, at least one
   * @return a validator restricted to those targets
   */
  static PostLogoutRedirectValidator allowOnly(URI... allowed) {
    requireNonNull(allowed, "allowed must not be null");
    if (allowed.length == 0) {
      throw new IllegalArgumentException(
          "allowOnly requires at least one URI — an empty allowlist rejects every logout redirect; "
              + "use permitAll() if that is what you mean");
    }
    Set<String> permitted = new LinkedHashSet<>();
    Arrays.stream(allowed)
        .map(uri -> requireNonNull(uri, "allowed must not contain null"))
        .map(PostLogoutRedirectValidator::normalize)
        .forEach(permitted::add);
    return candidate -> permitted.contains(normalize(candidate));
  }

  /** Scheme, host, port and path — the parts that decide where a browser goes. */
  private static String normalize(URI uri) {
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(java.util.Locale.ROOT);
    String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(java.util.Locale.ROOT);
    int port = uri.getPort();
    String path = uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath();
    return scheme + "://" + host + ":" + port + path;
  }
}
