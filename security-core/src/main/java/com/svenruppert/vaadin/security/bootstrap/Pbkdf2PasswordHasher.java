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
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PBKDF2-HMAC-SHA256 hasher using only JDK APIs. Encoded format:
 * {@code pbkdf2$<iterations>$<base64-salt>$<base64-hash>}.
 */
public final class Pbkdf2PasswordHasher implements PasswordHasher {

  private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int DEFAULT_ITERATIONS = 120_000;
  private static final int SALT_BYTES = 16;
  private static final int HASH_BITS = 256;

  /** Algorithm identifier exposed by {@link PasswordHash#algorithm()}. */
  public static final String ALGORITHM_ID = "pbkdf2";
  /** Parameter key — iteration count. */
  public static final String PARAM_ITERATIONS = "iterations";
  /** Parameter key — base64-encoded salt. */
  public static final String PARAM_SALT = "salt";

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

  @Override
  public PasswordHash parse(String storedHash) {
    if (storedHash == null) {
      throw new IllegalArgumentException("storedHash must not be null");
    }
    String[] parts = storedHash.split("\\$");
    if (parts.length != 4 || !ALGORITHM_ID.equals(parts[0])) {
      throw new IllegalArgumentException("Not a pbkdf2 hash");
    }
    try {
      int iterations = Integer.parseInt(parts[1]);
      Map<String, String> params = new LinkedHashMap<>();
      params.put(PARAM_ITERATIONS, Integer.toString(iterations));
      params.put(PARAM_SALT, parts[2]);
      return new PasswordHash(ALGORITHM_ID, parts[3], params);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Malformed iteration count", e);
    }
  }

  @Override
  public String serialize(PasswordHash hash) {
    if (hash == null) {
      throw new IllegalArgumentException("hash must not be null");
    }
    if (!ALGORITHM_ID.equals(hash.algorithm())) {
      throw new IllegalArgumentException("Unexpected algorithm: " + hash.algorithm());
    }
    int iterations = hash.intParameter(PARAM_ITERATIONS, -1);
    if (iterations <= 0) {
      throw new IllegalArgumentException("Missing/invalid iterations parameter");
    }
    String salt = hash.parameters().get(PARAM_SALT);
    if (salt == null || salt.isBlank()) {
      throw new IllegalArgumentException("Missing salt parameter");
    }
    return ALGORITHM_ID + "$" + iterations + "$" + salt + "$" + hash.encoded();
  }

  /**
   * @return {@code true} when {@code storedHash} is a pbkdf2 hash whose
   *         iteration count differs from this hasher's current
   *         {@code iterations}, or when its algorithm is not pbkdf2 at
   *         all (in which case re-hashing migrates the user to the
   *         current scheme on the next successful login).
   */
  @Override
  public boolean needsRehash(PasswordHash storedHash) {
    if (storedHash == null) {
      return false;
    }
    if (!ALGORITHM_ID.equals(storedHash.algorithm())) {
      return true;
    }
    int storedIterations = storedHash.intParameter(PARAM_ITERATIONS, -1);
    return storedIterations != iterations;
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
