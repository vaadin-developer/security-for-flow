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
package com.svenruppert.vaadin.security.bootstrap;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * PBKDF2-HMAC-SHA256 hasher using only JDK APIs. Encoded format:
 * {@code pbkdf2$<iterations>$<base64-salt>$<base64-hash>}.
 */
public final class Pbkdf2PasswordHasher implements PasswordHasher {

  private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int DEFAULT_ITERATIONS = 120_000;
  private static final int SALT_BYTES = 16;
  private static final int HASH_BITS = 256;

  private final int iterations;
  private final SecureRandom random;

  public Pbkdf2PasswordHasher() {
    this(DEFAULT_ITERATIONS, new SecureRandom());
  }

  public Pbkdf2PasswordHasher(int iterations, SecureRandom random) {
    this.iterations = iterations;
    this.random = random;
  }

  @Override
  public String hash(char[] rawPassword) {
    byte[] salt = new byte[SALT_BYTES];
    random.nextBytes(salt);
    byte[] hash = derive(rawPassword, salt, iterations);
    Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
    return "pbkdf2$" + iterations
        + "$" + encoder.encodeToString(salt)
        + "$" + encoder.encodeToString(hash);
  }

  @Override
  public boolean verify(char[] rawPassword, String storedHash) {
    if (storedHash == null) return false;
    String[] parts = storedHash.split("\\$");
    if (parts.length != 4 || !"pbkdf2".equals(parts[0])) return false;
    int storedIterations;
    byte[] salt;
    byte[] expected;
    try {
      storedIterations = Integer.parseInt(parts[1]);
      Base64.Decoder decoder = Base64.getDecoder();
      salt = decoder.decode(parts[2]);
      expected = decoder.decode(parts[3]);
    } catch (RuntimeException e) {
      return false;
    }
    byte[] candidate = derive(rawPassword, salt, storedIterations);
    return MessageDigest.isEqual(candidate, expected);
  }

  private static byte[] derive(char[] password, byte[] salt, int iterations) {
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
      return factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Password hashing failed", e);
    } finally {
      spec.clearPassword();
      Arrays.fill(salt, salt.length, salt.length, (byte) 0); // no-op, just keeps lifecycle obvious
    }
  }
}
