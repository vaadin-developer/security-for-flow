/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.token;

import java.util.Arrays;
import java.util.Objects;

/**
 * Persisted half of a {@link SelectorVerifierToken}: the non-secret
 * selector plus the digest of the verifier.
 *
 * <p>Defensive-copies the digest on construction. {@link #toString()}
 * never exposes the digest bytes (CWE-522 / CWE-209).</p>
 */
public record TokenDigestRecord(String selector, byte[] verifierDigest) {

  public TokenDigestRecord {
    Objects.requireNonNull(selector, "selector");
    if (selector.isBlank()) {
      throw new IllegalArgumentException("selector must not be blank");
    }
    Objects.requireNonNull(verifierDigest, "verifierDigest");
    if (verifierDigest.length == 0) {
      throw new IllegalArgumentException("verifierDigest must not be empty");
    }
    verifierDigest = verifierDigest.clone();
  }

  /**
   * Returns a fresh copy of the digest bytes.
   */
  public byte[] copyVerifierDigest() {
    return verifierDigest.clone();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof TokenDigestRecord that)) {
      return false;
    }
    return selector.equals(that.selector)
        && Arrays.equals(verifierDigest, that.verifierDigest);
  }

  @Override
  public int hashCode() {
    return selector.hashCode() * 31 + Arrays.hashCode(verifierDigest);
  }

  @Override
  public String toString() {
    return "TokenDigestRecord[selector=" + selector
        + ", digestLength=" + verifierDigest.length
        + ", verifierDigest=<redacted>]";
  }
}
