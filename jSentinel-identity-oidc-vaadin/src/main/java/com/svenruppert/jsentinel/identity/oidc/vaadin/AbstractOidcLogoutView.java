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
package com.svenruppert.jsentinel.identity.oidc.vaadin;

import com.svenruppert.jsentinel.identity.oidc.RpInitiatedLogoutInitiator;
import com.svenruppert.jsentinel.oidc.api.LogoutInitiator;
import com.svenruppert.jsentinel.oidc.api.LogoutRequest;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;

import java.net.URI;

/**
 * Reusable base for the Vaadin OIDC RP-initiated-logout route (V00.78). The
 * consumer maps it to a {@code @Route} (e.g. {@code "logout"}), tears down the local
 * session in {@link #onBeforeLogout()} and supplies the {@code end_session_endpoint}
 * + {@link LogoutRequest}; on entry it redirects the browser to the OP end-session
 * URL. Like the other Vaadin-runtime building blocks, the navigation glue is
 * exercised in the demo rather than unit-tested.
 */
public abstract class AbstractOidcLogoutView extends Div implements BeforeEnterObserver {

  private final LogoutInitiator initiator = new RpInitiatedLogoutInitiator();

  /** @return the OP {@code end_session_endpoint} (from discovery / config). */
  protected abstract URI endSessionEndpoint();

  /** @return the logout parameters (id_token_hint, post_logout_redirect_uri, state). */
  protected abstract LogoutRequest logoutRequest();

  /** Hook to clear the local session/subject before the redirect (default: no-op). */
  protected void onBeforeLogout() {
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    onBeforeLogout();
    URI redirect = initiator.buildLogoutUri(endSessionEndpoint(), logoutRequest());
    getUI().ifPresent(ui -> ui.getPage().setLocation(redirect.toString()));
  }
}
