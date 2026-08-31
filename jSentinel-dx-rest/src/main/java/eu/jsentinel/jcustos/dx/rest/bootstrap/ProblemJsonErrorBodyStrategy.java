/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;

/**
 * {@link RestErrorBodyStrategy} that emits RFC 7807
 * <em>application/problem+json</em> bodies for denial decisions.
 * Carries only the title + status; no subject, credential, or
 * stack-trace details — the same discipline as
 * {@link DefaultRestErrorBodyStrategy}.
 *
 * <p>Selected via the
 * {@code RestJSentinelBootstrap.problemJsonErrors()} convenience
 * method, or by passing this instance to
 * {@code .errorBodies(...)} directly.
 *
 * @since 00.74.00
 */
public final class ProblemJsonErrorBodyStrategy implements RestErrorBodyStrategy {

  /** Stateless singleton. */
  public static final ProblemJsonErrorBodyStrategy INSTANCE = new ProblemJsonErrorBodyStrategy();

  private ProblemJsonErrorBodyStrategy() {
  }

  @Override
  public String bodyFor(AuthorizationDecision decision) {
    return switch (decision) {
      case AuthorizationDecision.Granted ignored -> "";
      case AuthorizationDecision.Unauthenticated ignored ->
          problemJson("about:blank", "Unauthorized", HttpStatus.UNAUTHORIZED.code());
      case AuthorizationDecision.Forbidden ignored ->
          problemJson("about:blank", "Forbidden", HttpStatus.FORBIDDEN.code());
      case AuthorizationDecision.StepUpRequired ignored ->
          problemJson("about:blank", "Step-Up Required", HttpStatus.UNAUTHORIZED.code());
    };
  }

  private static String problemJson(String type, String title, int status) {
    return "{\"type\":\"" + escape(type)
        + "\",\"title\":\"" + escape(title)
        + "\",\"status\":" + status
        + "}";
  }

  private static String escape(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
