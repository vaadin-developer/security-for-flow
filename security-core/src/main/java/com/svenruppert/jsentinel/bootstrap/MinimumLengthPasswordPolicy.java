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

/**
 * Trivial password policy that only enforces a minimum length. Adequate as
 * a default; applications can plug stronger policies in.
 */
public final class MinimumLengthPasswordPolicy implements PasswordPolicy {

  private final int minLength;

  public MinimumLengthPasswordPolicy(int minLength) {
    if (minLength < 1) throw new IllegalArgumentException("minLength must be >= 1");
    this.minLength = minLength;
  }

  @Override
  public PasswordPolicyResult validate(char[] password) {
    if (password == null || password.length < minLength) {
      return PasswordPolicyResult.violation(
          "Password must be at least " + minLength + " characters long.");
    }
    return PasswordPolicyResult.ok();
  }
}
