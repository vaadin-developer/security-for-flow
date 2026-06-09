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
package com.svenruppert.jsentinel.credential.lifecycle;

/**
 * Adapter-neutral decision derived from a credential's current
 * lifecycle status.
 *
 * <p>The decision never references HTTP redirects, Vaadin routes or
 * any UI action. Adapters (Vaadin/REST/Standalone) own the mapping
 * from {@link CredentialLifecycleDecision} to a concrete user-visible
 * response (CWE-284).</p>
 */
public sealed interface CredentialLifecycleDecision
    permits CredentialLifecycleDecision.Proceed,
            CredentialLifecycleDecision.ForcePasswordChange,
            CredentialLifecycleDecision.ResetInProgress,
            CredentialLifecycleDecision.BlockedTemporary,
            CredentialLifecycleDecision.BlockedPermanent {

  /**
   * Normal login allowed. A rehash flag may still trigger a transparent
   * upgrade, but the lifecycle layer has nothing to add.
   */
  record Proceed() implements CredentialLifecycleDecision {
    public static final Proceed INSTANCE = new Proceed();
  }

  /**
   * Credentials verified, but the user must change the password before
   * the session may proceed.
   */
  record ForcePasswordChange() implements CredentialLifecycleDecision {
    public static final ForcePasswordChange INSTANCE = new ForcePasswordChange();
  }

  /**
   * A reset token is outstanding for this credential. Logins must use
   * the reset flow instead of the password flow until consumed.
   */
  record ResetInProgress() implements CredentialLifecycleDecision {
    public static final ResetInProgress INSTANCE = new ResetInProgress();
  }

  /**
   * Temporary block (typically {@code LOCKED}). The adapter surfaces
   * this as a generic "try again later" without revealing the lockout
   * counter (CWE-203).
   */
  record BlockedTemporary() implements CredentialLifecycleDecision {
    public static final BlockedTemporary INSTANCE = new BlockedTemporary();
  }

  /**
   * Permanent block (typically {@code COMPROMISED} or {@code DISABLED}).
   * Adapters surface this as a generic failure too — the differentiated
   * reason stays in audit (CWE-284).
   */
  record BlockedPermanent() implements CredentialLifecycleDecision {
    public static final BlockedPermanent INSTANCE = new BlockedPermanent();
  }
}
