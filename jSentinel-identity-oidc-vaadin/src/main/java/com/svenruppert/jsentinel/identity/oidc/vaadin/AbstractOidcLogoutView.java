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

import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.identity.oidc.RpInitiatedLogoutInitiator;
import com.svenruppert.jsentinel.oidc.api.LogoutInitiator;
import com.svenruppert.jsentinel.oidc.api.LogoutRequest;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;

import java.net.URI;
import java.util.Optional;

/**
 * Reusable base for the Vaadin OIDC RP-initiated-logout route (V00.78). The
 * consumer maps it to a {@code @Route} (e.g. {@code "logout"}) and supplies the
 * {@code end_session_endpoint} + {@link LogoutRequest}; on entry it clears the local
 * subject (JS-SEC-028), invokes the {@link #onBeforeLogout()} hook, and redirects the
 * browser to the OP end-session URL. Like the other Vaadin-runtime building blocks, the
 * navigation glue is exercised in the demo rather than unit-tested.
 */
public abstract class AbstractOidcLogoutView extends Div implements BeforeEnterObserver {

  private final LogoutInitiator initiator = new RpInitiatedLogoutInitiator();

  /** @return the OP {@code end_session_endpoint} (from discovery / config). */
  protected abstract URI endSessionEndpoint();

  /** @return the logout parameters (id_token_hint, post_logout_redirect_uri, state). */
  protected abstract LogoutRequest logoutRequest();

  /**
   * Additional teardown hook, run after the default local-subject clear and before the
   * redirect (default: no-op).
   *
   * @implSpec The base {@link #beforeEnter} already clears the current subject from the
   *     {@code SubjectStore} (JS-SEC-028) so a logout never leaves the RP session
   *     authenticated after the OP session ends. Override this for <em>extra</em>
   *     teardown; do not treat it as the <em>only</em> teardown path.
   */
  protected void onBeforeLogout() {
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    // JS-SEC-028 (CWE-613): tear down the local session by default so a "logout"
    // never leaves the RP session authenticated after the OP session ends.
    clearLocalSubject();
    onBeforeLogout();
    URI redirect = initiator.buildLogoutUri(endSessionEndpoint(), logoutRequest());
    getUI().ifPresent(ui -> ui.getPage().setLocation(redirect.toString()));
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static void clearLocalSubject() {
    try {
      Optional<SubjectStore> store = SubjectStores.findSubjectStore();
      if (store.isEmpty()) {
        return;
      }
      Class<?> subjectType;
      try {
        subjectType = JSentinelServiceResolver.<Object, Object>authenticationService().subjectType();
      } catch (RuntimeException ignored) {
        return;
      }
      Class raw = subjectType;
      store.get().deleteCurrentSubject(raw);
    } catch (RuntimeException ignored) {
      // never block the logout redirect on a teardown failure
    }
  }
}
