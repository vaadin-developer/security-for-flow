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
package eu.jsentinel.jcustos.bruteforce;

/**
 * Default {@link LoginAttemptPolicy} — never throttles, never records.
 * Used as the resolver fallback when no SPI implementation is registered.
 */
public final class NoopLoginAttemptPolicy implements LoginAttemptPolicy {

  /** Singleton instance. */
  public static final NoopLoginAttemptPolicy INSTANCE = new NoopLoginAttemptPolicy();

  /** Public for {@link java.util.ServiceLoader} discovery. Prefer {@link #INSTANCE}. */
  public NoopLoginAttemptPolicy() {
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    return LoginAttemptDecision.allowed();
  }

  @Override
  public void recordSuccess(LoginAttemptContext context) {
    // intentionally empty
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    // intentionally empty
  }
}
