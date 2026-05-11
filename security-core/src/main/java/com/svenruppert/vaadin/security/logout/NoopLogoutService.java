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
 * Default {@link LogoutService} — discards every call. Returned by
 * {@link SecurityServiceResolver#logoutService()} when no real
 * implementation has been registered.
 * <p>
 * Production applications must register a concrete
 * {@link SubjectClearingLogoutService} (or an adapter-specific subclass)
 * during startup. The noop fallback exists so the resolver never
 * throws — logout is optional infrastructure, like audit.
 */
public final class NoopLogoutService implements LogoutService {

  /** Singleton instance. */
  public static final NoopLogoutService INSTANCE = new NoopLogoutService();

  /** Public for {@link java.util.ServiceLoader} discovery. Prefer {@link #INSTANCE}. */
  public NoopLogoutService() {
  }

  @Override
  public void logout(SubjectId subjectId, LogoutScope scope) {
    // intentionally empty
  }

  @Override
  public void addListener(LogoutListener listener) {
    // intentionally empty
  }

  @Override
  public void removeListener(LogoutListener listener) {
    // intentionally empty
  }
}
