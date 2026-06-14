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
package com.svenruppert.jsentinel.bootstrap;

import java.util.OptionalInt;

/**
 * Validates a candidate password against the minimum acceptance rules.
 * Applications can plug stronger policies in.
 */
public interface PasswordPolicy {

  PasswordPolicyResult validate(char[] password);

  /**
   * Hint for UI surfaces. Returns the lower bound this policy enforces in
   * characters, or {@link OptionalInt#empty()} when the policy is not
   * length-based.
   * <p>
   * The framework does not call this method during validation — it is
   * purely informational for consumer-side UI hints (helper text on a
   * password field, optional client-side pre-checks). A single source of
   * truth so the UI hint and the server-side policy cannot drift.
   *
   * @return optional minimum length, empty when this policy does not
   *         enforce a length floor.
   * @since 00.74.10
   */
  default OptionalInt minLength() {
    return OptionalInt.empty();
  }

  record PasswordPolicyResult(boolean valid, String reason) {
    public static PasswordPolicyResult ok() {
      return new PasswordPolicyResult(true, null);
    }

    public static PasswordPolicyResult violation(String reason) {
      return new PasswordPolicyResult(false, reason);
    }
  }
}
