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
package eu.jsentinel.jcustos.bootstrap;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;

/**
 * Generates fresh {@link BootstrapToken}s using {@link SecureRandom} and a
 * 32-character ambiguity-free alphabet (drops {@code O 0 I 1}). Token shape
 * is {@code XXXX-XXXX-XXXX-XXXX-XXXX} which yields ~100 bits of entropy.
 */
public final class BootstrapTokenGenerator {

  private static final char[] ALPHABET =
      "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
  private static final int GROUPS = 5;
  private static final int GROUP_LENGTH = 4;

  private final SecureRandom random;
  private final Clock clock;

  public BootstrapTokenGenerator() {
    this(new SecureRandom(), Clock.systemUTC());
  }

  public BootstrapTokenGenerator(SecureRandom random, Clock clock) {
    this.random = random;
    this.clock = clock;
  }

  public BootstrapToken generate() {
    StringBuilder sb = new StringBuilder(GROUPS * (GROUP_LENGTH + 1) - 1);
    for (int g = 0; g < GROUPS; g++) {
      if (g > 0) sb.append('-');
      for (int i = 0; i < GROUP_LENGTH; i++) {
        sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
      }
    }
    return new BootstrapToken(sb.toString(), Instant.now(clock));
  }
}
