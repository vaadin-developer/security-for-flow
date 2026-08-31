package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Computes the canonical-payload hash bound into the envelope (Konzept §342).
 */
final class PayloadDigest {

  private PayloadDigest() {
  }

  static String hash(PayloadHashAlgorithm algorithm, byte[] canonicalPayload) {
    try {
      MessageDigest digest = MessageDigest.getInstance(algorithm.value());
      return HexFormat.of().formatHex(digest.digest(canonicalPayload));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Payload hash algorithm unavailable: " + algorithm.value(), e);
    }
  }

  /**
   * JS-SEC-054 (CWE-755): soft variant for the verify path. The envelope carries an
   * attacker-influenced {@code payloadHashAlgorithm} that accepts any non-blank string, so an
   * unavailable JCA name must yield a fail-closed verification result rather than an uncaught
   * {@link IllegalStateException} escaping the (documented-total) {@code verify()}.
   *
   * @return the hex digest, or empty if the algorithm is unavailable
   */
  static Optional<String> tryHash(PayloadHashAlgorithm algorithm, byte[] canonicalPayload) {
    try {
      return Optional.of(hash(algorithm, canonicalPayload));
    } catch (RuntimeException unavailable) {
      return Optional.empty();
    }
  }
}
