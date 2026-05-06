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
package com.svenruppert.vaadin.security.authorization.api;

import java.util.Objects;

/**
 * Behaviour switches for {@link LogoutService}.
 * <p>
 * The core never inspects {@code closeVaadinSession} /
 * {@code invalidateHttpSession} on its own — these flags are consumed by
 * adapter implementations (e.g. {@code VaadinLogoutService}). When
 * {@link #clearSubjectOnly()} is {@code true} the adapter must skip both
 * session-invalidation flags.
 *
 * @param targetRoute            where to navigate after logout (route id /
 *                               URL path; never null/blank)
 * @param closeVaadinSession     close the Vaadin session
 * @param invalidateHttpSession  invalidate the underlying servlet session
 * @param clearSubjectOnly       skip session invalidation; only drop the
 *                               subject from the subject store
 */
public record LogoutPolicy(
    String targetRoute,
    boolean closeVaadinSession,
    boolean invalidateHttpSession,
    boolean clearSubjectOnly
) {

  public LogoutPolicy {
    Objects.requireNonNull(targetRoute, "targetRoute");
    if (targetRoute.isBlank()) {
      throw new IllegalArgumentException("targetRoute must not be blank");
    }
    if (clearSubjectOnly && (closeVaadinSession || invalidateHttpSession)) {
      throw new IllegalArgumentException(
          "clearSubjectOnly is incompatible with session invalidation flags");
    }
  }

  /** Drops the subject only. Sessions stay alive. */
  public static LogoutPolicy clearSubjectOnly(String targetRoute) {
    return new LogoutPolicy(targetRoute, false, false, true);
  }

  /** Drops the subject and invalidates Vaadin + HTTP session. */
  public static LogoutPolicy fullInvalidate(String targetRoute) {
    return new LogoutPolicy(targetRoute, true, true, false);
  }

  /** Drops the subject and the HTTP session, but keeps the Vaadin session. */
  public static LogoutPolicy invalidateHttpSession(String targetRoute) {
    return new LogoutPolicy(targetRoute, false, true, false);
  }
}
