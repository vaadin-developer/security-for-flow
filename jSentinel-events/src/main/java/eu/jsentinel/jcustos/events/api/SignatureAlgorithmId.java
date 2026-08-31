package eu.jsentinel.jcustos.events.api;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Stable wire identifier of the signature algorithm used for an envelope.
 *
 * <p>Stored on the envelope (rather than a live SPI reference) so envelopes
 * stay serialization-friendly. The {@code SignatureAlgorithm} SPI exposes its
 * own {@code id()} of this type; the verifier resolves the concrete algorithm
 * from this identifier.
 *
 * @param value non-blank algorithm identifier
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record SignatureAlgorithmId(String value) {

  /** Default asymmetric signature algorithm (Konzept §384). */
  public static final SignatureAlgorithmId ED25519 = new SignatureAlgorithmId("Ed25519");

  /** Optional fallback for JDK distributions lacking Ed25519 (Konzept §390). */
  public static final SignatureAlgorithmId ECDSA_P256 = new SignatureAlgorithmId("SHA256withECDSA");

  public SignatureAlgorithmId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("SignatureAlgorithmId value must not be null or blank");
    }
  }

  public static SignatureAlgorithmId of(String value) {
    return new SignatureAlgorithmId(value);
  }
}
