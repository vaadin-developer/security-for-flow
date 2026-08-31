/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.change;

/**
 * Adapter-neutral instruction returned after a successful password
 * change. Adapters (Vaadin / REST / Standalone) map this to a concrete
 * session lifecycle action.
 *
 * <p>The default decision is
 * {@link #INVALIDATE_OTHER_SESSIONS} — the new credential should not
 * extend the lifetime of sessions that were authenticated with the
 * old one (CWE-613).</p>
 */
public enum SessionHandlingDecision {
  /**
   * Keep the current session; invalidate every other active session.
   */
  INVALIDATE_OTHER_SESSIONS,

  /**
   * Keep every session. Reserved for cases where the operator
   * explicitly tolerates parallel sessions (e.g. operator-driven
   * change without re-authentication).
   */
  KEEP_SESSIONS
}
