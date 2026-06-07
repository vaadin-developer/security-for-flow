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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.authentication.PasswordHasher;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Deterministic {@link PasswordHasher} backed by SHA-256.
 * Suitable for hashing single-use account-lifecycle tokens
 * (password reset, email verification) where:
 * <ul>
 *   <li>the input already carries 256+ bits of entropy
 *       (random per-issuance, server-generated), so no per-record
 *       salt is needed; and</li>
 *   <li>the {@link com.svenruppert.vaadin.security.accountlifecycle.PasswordResetTokenStore}
 *       performs constant-time-by-hash lookups, which requires
 *       a deterministic hash function.</li>
 * </ul>
 * <p>
 * <em>Not</em> a password hasher — never use this for human-chosen
 * passwords. The Pbkdf2/Argon2id providers wired through
 * {@code PasswordHashingServices.defaults()} are what you want
 * there.
 */
public final class Sha256TokenHasher implements PasswordHasher {

  @Override
  public String hash(char[] rawPassword) {
    if (rawPassword == null) {
      throw new IllegalArgumentException("rawPassword must not be null");
    }
    byte[] input = new String(rawPassword).getBytes(StandardCharsets.UTF_8);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(input));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 must be available", e);
    }
  }

  @Override
  public boolean verify(char[] rawPassword, String storedHash) {
    if (rawPassword == null || storedHash == null) {
      return false;
    }
    String candidate = hash(rawPassword);
    // Constant-time comparison.
    return MessageDigest.isEqual(
        candidate.getBytes(StandardCharsets.UTF_8),
        storedHash.getBytes(StandardCharsets.UTF_8));
  }
}
