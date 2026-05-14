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
package com.svenruppert.vaadin.security.logout;

/**
 * Consumer-side callback for {@link LogoutService} events.
 * <p>
 * The Vaadin adapter registers a listener that invalidates the active
 * {@code VaadinSession} (via {@code VaadinSessionSubjectStore} in the
 * {@code security-vaadin} module); the REST adapter registers a listener
 * that revokes the bearer token. Listeners must not throw — the
 * {@link LogoutService} will swallow any exception so a misbehaving
 * listener cannot block the logout flow.
 */
@FunctionalInterface
public interface LogoutListener {

  /**
   * Fired once per logged-out session. For
   * {@link LogoutScope#AllSessionsOfSubject AllSessionsOfSubject}, the
   * listener is invoked once per session id in the registry.
   *
   * @param subjectId subject being logged out
   * @param sessionId session being logged out; may be {@code null} when
   *                  the caller did not supply a current session id
   *                  (e.g. background-thread logout)
   * @param scope     the requested scope
   */
  void onLogout(SubjectId subjectId, String sessionId, LogoutScope scope);
}
