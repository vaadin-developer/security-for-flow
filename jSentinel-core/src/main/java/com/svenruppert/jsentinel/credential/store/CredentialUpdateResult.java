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
package com.svenruppert.jsentinel.credential.store;

import java.util.Objects;

/**
 * Outcome of a compare-and-swap update against the
 * {@link CredentialStore}.
 *
 * <p>Sealed so callers pattern-match exhaustively. {@link Stale} is
 * returned when the witness no longer matches the persisted record —
 * typically because another concurrent verifier rehashed it first.
 * Stale is <em>not</em> a security failure; the caller should re-read,
 * decide whether to rehash again, and proceed or skip.</p>
 *
 * <p>Update methods never throw on race or absence; they always
 * collapse to one of these variants so audit timelines stay clean
 * (CWE-362 / CWE-367).</p>
 */
public sealed interface CredentialUpdateResult
    permits CredentialUpdateResult.Updated,
            CredentialUpdateResult.Stale,
            CredentialUpdateResult.NotFound {

  /**
   * The CAS succeeded; {@code newRecord} is the value now stored.
   */
  record Updated(CredentialRecord newRecord) implements CredentialUpdateResult {

    public Updated {
      Objects.requireNonNull(newRecord, "newRecord");
    }
  }

  /**
   * The witness did not match the persisted record. The store was not
   * modified.
   */
  record Stale() implements CredentialUpdateResult {
    public static final Stale INSTANCE = new Stale();
  }

  /**
   * No record existed under the supplied username. The store was not
   * modified.
   */
  record NotFound() implements CredentialUpdateResult {
    public static final NotFound INSTANCE = new NotFound();
  }
}
