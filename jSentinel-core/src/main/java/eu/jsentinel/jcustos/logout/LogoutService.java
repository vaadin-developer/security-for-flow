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
package eu.jsentinel.jcustos.logout;

/**
 * Bundles the logout flow so callers do not have to manually orchestrate
 * subject removal, session invalidation and navigation.
 * <p>
 * The {@link #logout(SubjectId, LogoutScope)} call has two pieces:
 * <ul>
 *   <li>{@link LogoutScope#CurrentSession CurrentSession} — log the
 *       subject out of the session associated with the caller.</li>
 *   <li>{@link LogoutScope#AllSessionsOfSubject AllSessionsOfSubject}
 *       — log the subject out of every active session, enumerated via
 *       the {@link SubjectSessionRegistry}.</li>
 * </ul>
 *
 * <p>Adapters that care about session invalidation register a
 * {@link LogoutListener} via {@link #addListener(LogoutListener)}. The
 * Vaadin adapter listens to invalidate the {@code VaadinSession} and
 * close the underlying servlet session; the REST adapter listens to
 * revoke the bearer token.
 *
 * <p>The core implementation
 * ({@link SubjectClearingLogoutService}) clears the subject from the
 * {@link eu.jsentinel.jcustos.authorization.api.SubjectStore},
 * consults the registry, and fans out the notification to every
 * registered listener. It does not know about Vaadin sessions, HTTP
 * sessions, or any specific transport.
 */
public interface LogoutService {

  /**
   * Performs the logout.
   *
   * @param subjectId subject to log out; non-{@code null}
   * @param scope     scope of the logout; non-{@code null}
   */
  void logout(SubjectId subjectId, LogoutScope scope);

  /**
   * Registers a listener that gets notified once per logged-out
   * session id. Idempotent — registering the same listener twice is a
   * no-op.
   *
   * @param listener non-{@code null}
   */
  void addListener(LogoutListener listener);

  /**
   * Removes a previously registered listener. No-op when the listener
   * was never registered.
   *
   * @param listener listener to remove
   */
  void removeListener(LogoutListener listener);
}
