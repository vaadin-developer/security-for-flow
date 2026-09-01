package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;

/**
 * Turns an {@link AuthorizationDecision} into an HTTP response.
 *
 * <p>This is the seam {@code RestAuthorizationFilter} enforces through.
 * It lives in {@code jCustos-rest} rather than in the DX module so the
 * filter can accept an application-supplied mapper without the
 * enforcement layer depending on the bootstrap layer — the dependency
 * runs {@code core → rest → dx-rest} and must keep running that way.
 *
 * <p>{@code jCustos-dx-rest} exposes this contract as
 * {@code RestDecisionMapper}, which extends it; a mapper written
 * against either name works with both.
 *
 * @since 00.83.00
 */
@FunctionalInterface
public interface RestDecisionMapping {

  /**
   * Applies a decision to the response.
   *
   * @param decision the decision to render
   * @param response the response to write to
   * @return {@code true} if the protected handler may continue
   */
  boolean apply(AuthorizationDecision decision, RestResponse response);
}
