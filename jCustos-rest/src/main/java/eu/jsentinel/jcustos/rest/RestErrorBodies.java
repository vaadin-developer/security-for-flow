package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;

/**
 * Supplies the response body for a denied {@link AuthorizationDecision}.
 *
 * <p>Separating the body from the status lets an application change the
 * wire format — RFC 7807 {@code application/problem+json}, say — without
 * reimplementing the status and challenge-header logic that
 * {@link HttpStatusDecisionMapper} already gets right.
 *
 * <p>{@code jCustos-dx-rest} exposes this contract as
 * {@code RestErrorBodyStrategy}, which extends it.
 *
 * @since 00.83.00
 */
@FunctionalInterface
public interface RestErrorBodies {

  /**
   * @param decision the denial being rendered; never {@code Granted}
   * @return the body to write, never {@code null}
   */
  String bodyFor(AuthorizationDecision decision);

  /**
   * The conservative default: short, generic strings that leak nothing
   * about why a request was denied.
   *
   * @return the default strategy
   */
  static RestErrorBodies generic() {
    return decision -> switch (decision) {
      case AuthorizationDecision.Granted() -> "";
      case AuthorizationDecision.Forbidden(String ignored) -> "Forbidden";
      default -> "Unauthorized";
    };
  }
}
