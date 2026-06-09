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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteUser;
import com.vaadin.flow.server.VaadinSession;

import java.util.Optional;

/**
 * Vaadin-session-backed token + subject holder. The token is kept under a
 * private session attribute key; the {@link RemoteUser} is stored via the
 * existing {@link SubjectStores} so the framework's
 * {@code AuthorizationListener} can pick it up just like any other subject.
 */
public final class ClientJSentinelContext {

  private static final String TOKEN_KEY = ClientJSentinelContext.class.getName() + ".token";

  private ClientJSentinelContext() {
  }

  public static void setActiveLogin(String token, RemoteUser user) {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) session.setAttribute(TOKEN_KEY, token);
    SubjectStores.subjectStore().setCurrentSubject(user, RemoteUser.class);
  }

  public static Optional<String> token() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) return Optional.empty();
    Object value = session.getAttribute(TOKEN_KEY);
    return value instanceof String s && !s.isBlank() ? Optional.of(s) : Optional.empty();
  }

  public static Optional<RemoteUser> user() {
    return SubjectStores.subjectStore().currentSubject(RemoteUser.class);
  }

  public static void clear() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) session.setAttribute(TOKEN_KEY, null);
    SubjectStores.subjectStore().deleteCurrentSubject(RemoteUser.class);
  }
}
