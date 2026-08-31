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
package eu.jsentinel.jcustos.oauth2.vaadin;

/*-
 * #%L
 * jCustos OAuth2 — Vaadin callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Reusable base for the Vaadin OAuth2 redirect-callback route (Konzept §6.5,
 * V00.77). The consumer maps it to a {@code @Route} (e.g. {@code "oauth2/callback"})
 * and supplies the {@link AuthorizationCodeFlow}, a token sink and the post-login
 * navigation target. On entry it reads {@code code} + {@code state} (or
 * {@code error}) from the query string, drives the flow (single-use state + PKCE
 * exchange) and forwards to {@link #successTarget()} or {@link #errorTarget()} —
 * tokens are never rendered into the page.
 *
 * <p>Like the other Vaadin-runtime building blocks (e.g. {@code LoginView}), the
 * navigation glue is exercised end-to-end in the demo rather than unit-tested;
 * the testable security primitive is {@link VaadinSessionStateStore}.
 */
public abstract class AbstractOAuth2CallbackView extends Div implements BeforeEnterObserver {

  /** @return the configured authorization-code flow (state store + token client). */
  protected abstract AuthorizationCodeFlow flow();

  /**
   * Binds the callback outcome (e.g. into the session / subject store). JS-SEC-059: the argument is
   * a {@link CallbackResult} — {@code result.tokens()} plus the stored {@code nonce()} and
   * {@code resumeTarget()} — so an overriding view that validates the {@code id_token} can enforce
   * the nonce via {@code IdTokenExpectations.of(issuer, audience, result.nonce())}.
   */
  protected abstract void onTokens(CallbackResult result);

  /** @return the route to forward to after a successful login. */
  protected abstract String successTarget();

  /** @return the route to forward to on any callback failure (default: the app root). */
  protected String errorTarget() {
    return "";
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    Map<String, List<String>> query = event.getLocation().getQueryParameters().getParameters();
    String state = first(query, "state");
    if (state == null || state.isBlank()) {
      event.forwardTo(errorTarget());
      return;
    }
    AuthorizationCodeFlow.CallbackParams params = new AuthorizationCodeFlow.CallbackParams(
        opt(first(query, "code")), state, opt(first(query, "error")),
        opt(first(query, "error_description")));

    Result<CallbackResult, OAuth2Error> result = flow().handleCallback(params);
    if (result.isSuccess()) {
      onTokens(result.toOptional().orElseThrow());
      event.forwardTo(successTarget());
    } else {
      event.forwardTo(errorTarget());
    }
  }

  private static String first(Map<String, List<String>> query, String key) {
    List<String> values = query.get(key);
    return (values == null || values.isEmpty()) ? null : values.get(0);
  }

  private static Optional<String> opt(String value) {
    return (value == null || value.isBlank()) ? Optional.empty() : Optional.of(value);
  }
}
