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
package com.svenruppert.jsentinel.logout;

/**
 * Scope of a logout request.
 */
public enum LogoutScope {

  /**
   * Log the subject out of the session associated with the current
   * thread / request. The most common user-initiated logout — a sign-out
   * button.
   */
  CurrentSession,

  /**
   * Log the subject out of every active session for that subject.
   * Used for administrative "force-sign-out everywhere" actions or
   * when a session-fixation / password-change event invalidates all
   * existing sessions.
   */
  AllSessionsOfSubject
}
