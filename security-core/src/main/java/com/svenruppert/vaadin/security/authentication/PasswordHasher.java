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
package com.svenruppert.vaadin.security.authentication;

/**
 * Password hashing abstraction. The bootstrap service hashes the raw
 * administrator password before handing it to the application's
 * {@link com.svenruppert.vaadin.security.bootstrap.AdministratorAccountStore}.
 * Plaintext passwords are never stored.
 * <p>
 * Two parallel APIs are exposed:
 * <ul>
 *   <li>The original {@code String}-based pair
 *       ({@link #hash(char[])} / {@link #verify(char[], String)}) — used
 *       by callers that persist the hash as a single opaque string.</li>
 *   <li>A typed pair ({@link #hashTo(char[])} /
 *       {@link #verify(char[], PasswordHash)} /
 *       {@link #needsRehash(PasswordHash)}) — used by callers that want
 *       to inspect algorithm parameters or detect drift between the
 *       hasher's current parameters and an existing stored hash.</li>
 * </ul>
 *
 * <p>Default implementations bridge between the two views via a hasher's
 * own wire format, so applications can pick whichever shape fits their
 * persistence layer without forcing a second SPI.
 */
public interface PasswordHasher {

  /** Hashes the password and returns the implementation's wire format. */
  String hash(char[] rawPassword);

  /** Verifies a candidate password against a wire-format stored hash. */
  boolean verify(char[] rawPassword, String storedHash);

  /**
   * Hashes the password and returns the parsed {@link PasswordHash}
   * (algorithm + encoded bytes + parameters). The default implementation
   * delegates to {@link #hash(char[])} and parses the result via
   * {@link #parse(String)}.
   *
   * @param rawPassword cleared by the caller; the hasher must not retain it
   * @return typed hash
   */
  default PasswordHash hashTo(char[] rawPassword) {
    return parse(hash(rawPassword));
  }

  /**
   * Verifies a candidate password against a typed {@link PasswordHash}.
   * Default delegates to {@link #verify(char[], String)} via
   * {@link #serialize(PasswordHash)}.
   *
   * @param rawPassword candidate
   * @param storedHash  previously stored hash
   * @return {@code true} if the candidate matches
   */
  default boolean verify(char[] rawPassword, PasswordHash storedHash) {
    return verify(rawPassword, serialize(storedHash));
  }

  /**
   * Reports whether {@code storedHash} was produced with parameters that
   * differ from this hasher's current configuration. Callers that want
   * to upgrade weak or outdated hashes should re-hash on the next
   * successful login when this returns {@code true}.
   * <p>
   * The default returns {@code false} (no drift detection). Concrete
   * implementations like {@link Pbkdf2PasswordHasher} compare the
   * hash's algorithm + iteration count against their own.
   *
   * @param storedHash previously stored hash; never {@code null}
   * @return {@code true} when a re-hash is recommended
   */
  default boolean needsRehash(PasswordHash storedHash) {
    return false;
  }

  /**
   * Convenience: parses {@code storedHash} via {@link #parse(String)}
   * and delegates to {@link #needsRehash(PasswordHash)}.
   * <p>
   * Returns {@code false} for {@code null} input or when the hasher
   * cannot parse the stored format ({@link UnsupportedOperationException}
   * from the default {@code parse}, or any
   * {@link IllegalArgumentException} the implementation may raise on
   * malformed input). Failure to parse is not an error worth aborting
   * the login flow over — the caller already has a successfully verified
   * hash, so the worst case is "we couldn't upgrade it on this login".
   *
   * @param storedHash wire-format stored hash, may be {@code null}
   * @return {@code true} when a re-hash is recommended
   */
  default boolean needsRehash(String storedHash) {
    if (storedHash == null) {
      return false;
    }
    try {
      return needsRehash(parse(storedHash));
    } catch (UnsupportedOperationException | IllegalArgumentException ignored) {
      return false;
    }
  }

  /**
   * Parses a wire-format hash into a {@link PasswordHash}. Implementations
   * that override the typed API must override this method too. Default
   * throws — the default implementations of {@link #hashTo(char[])} and
   * {@link #verify(char[], PasswordHash)} call this, so a hasher that
   * provides only the {@code String} pair must override either the
   * default methods or this one to participate in the typed API.
   *
   * @param storedHash wire-format hash
   * @return parsed typed hash
   */
  default PasswordHash parse(String storedHash) {
    throw new UnsupportedOperationException(
        getClass().getSimpleName() + " does not implement parse(String)");
  }

  /**
   * Inverse of {@link #parse(String)}. Default throws.
   *
   * @param hash typed hash
   * @return wire-format string suitable for {@link #verify(char[], String)}
   */
  default String serialize(PasswordHash hash) {
    throw new UnsupportedOperationException(
        getClass().getSimpleName() + " does not implement serialize(PasswordHash)");
  }
}
