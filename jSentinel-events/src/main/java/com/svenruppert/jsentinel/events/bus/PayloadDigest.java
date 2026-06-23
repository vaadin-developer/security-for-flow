package com.svenruppert.jsentinel.events.bus;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

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
}
