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
package com.svenruppert.jsentinel.authorization.api;

/**
 * Semantic adapter-neutral authorization decision.
 * <p>
 * This type intentionally contains no Vaadin routes and no HTTP status codes.
 * Adapter modules map it to framework-specific behavior.
 *
 * <p><strong>Canonical cross-adapter mapping (V00.75.20 R024).</strong> Every
 * adapter handles all four sealed variants exhaustively (no silent default).
 * {@code StepUpRequired} is deliberately <em>adapter-shaped</em> — there is no
 * single transport-neutral representation of a step-up challenge, so each
 * adapter renders it in its own idiom while preserving the {@code method}:
 *
 * <table border="1">
 *   <caption>{@code AuthorizationDecision} &rarr; adapter behavior</caption>
 *   <tr>
 *     <th>Variant</th>
 *     <th>REST ({@code HttpStatusDecisionMapper})</th>
 *     <th>Vaadin ({@code AuthorizationListener#map})</th>
 *     <th>Standalone ({@code JSentinelEnforcer#handle})</th>
 *   </tr>
 *   <tr>
 *     <td>{@link Granted}</td>
 *     <td>handler runs (returns {@code true})</td>
 *     <td>navigation continues</td>
 *     <td>delegate / {@code super} call proceeds</td>
 *   </tr>
 *   <tr>
 *     <td>{@link Unauthenticated}</td>
 *     <td>{@code 401} + body {@code "Unauthorized"}</td>
 *     <td>reroute to {@code loginRouteName()} (R025)</td>
 *     <td>{@code AccessDeniedException} {@code "Unauthenticated: …"}</td>
 *   </tr>
 *   <tr>
 *     <td>{@link Forbidden}</td>
 *     <td>{@code 403} + body {@code "Forbidden"}</td>
 *     <td>error view, generic {@code "Access denied"} (R018)</td>
 *     <td>{@code AccessDeniedException} carrying the reason</td>
 *   </tr>
 *   <tr>
 *     <td>{@link StepUpRequired}</td>
 *     <td>{@code 401} + {@code WWW-Authenticate: StepUp method="…"}</td>
 *     <td>reroute to {@code stepUpRouteName()}</td>
 *     <td>{@code AccessDeniedException} {@code "Step-up required: method=…"}</td>
 *   </tr>
 * </table>
 */
public sealed interface AuthorizationDecision
    permits AuthorizationDecision.Granted,
            AuthorizationDecision.Unauthenticated,
            AuthorizationDecision.Forbidden,
            AuthorizationDecision.StepUpRequired {

  /**
   * Access is granted.
   */
  record Granted() implements AuthorizationDecision {
  }

  /**
   * No authenticated subject is available.
   *
   * @param reason generic reason for diagnostics
   */
  record Unauthenticated(String reason) implements AuthorizationDecision {
  }

  /**
   * A subject is available but lacks the required authority.
   *
   * @param reason generic reason for diagnostics
   */
  record Forbidden(String reason) implements AuthorizationDecision {
  }

  /**
   * A subject is authenticated but a step-up challenge is required
   * before access can be granted. Adapters map this to a protocol-
   * specific challenge — REST emits {@code 401 Unauthorized} with a
   * {@code WWW-Authenticate: <method>} header, the Vaadin adapter
   * reroutes to a configurable step-up route.
   *
   * @param reason adapter-neutral diagnostic, may be empty
   * @param method step-up mechanism the adapter should challenge for
   *               (e.g. {@code "MFA"}, {@code "REAUTH"})
   */
  record StepUpRequired(String reason, String method) implements AuthorizationDecision {
    public StepUpRequired {
      reason = reason == null ? "" : reason;
      if (method == null || method.isBlank()) {
        throw new IllegalArgumentException("method must not be blank");
      }
      // JS-SEC-013 (CWE-113): `method` flows verbatim into a WWW-Authenticate
      // header on the REST adapter. Reject anything outside the RFC 7235 token
      // set — CR/LF, whitespace, quotes, backslash, control chars — so an
      // evaluator deriving it from request input cannot split the response.
      for (int i = 0; i < method.length(); i++) {
        if (!isToken(method.charAt(i))) {
          throw new IllegalArgumentException(
              "method must be an RFC 7235 token (no CR/LF, whitespace, quotes or control chars)");
        }
      }
    }

    private static boolean isToken(char c) {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
          || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }
  }

  /**
   * Creates a granted decision.
   *
   * @return granted
   */
  static AuthorizationDecision granted() {
    return new Granted();
  }

  /**
   * Creates an unauthenticated decision.
   *
   * @param reason generic reason
   * @return unauthenticated
   */
  static AuthorizationDecision unauthenticated(String reason) {
    return new Unauthenticated(reason);
  }

  /**
   * Creates a forbidden decision.
   *
   * @param reason generic reason
   * @return forbidden
   */
  static AuthorizationDecision forbidden(String reason) {
    return new Forbidden(reason);
  }

  /**
   * Creates a step-up-required decision.
   *
   * @param reason adapter-neutral diagnostic; {@code null} becomes empty string
   * @param method non-blank step-up mechanism (e.g. {@code "MFA"})
   * @return step-up-required
   */
  static AuthorizationDecision stepUpRequired(String reason, String method) {
    return new StepUpRequired(reason, method);
  }
}
