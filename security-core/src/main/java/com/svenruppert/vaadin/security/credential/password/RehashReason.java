/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
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

package com.svenruppert.vaadin.security.credential.password;


/**
 * Concrete reason that causes a stored credential to be flagged for
 * transparent rehashing on the next successful verification.
 *
 * <p>The reasons are deliberately mutually exclusive at decision time:
 * the active policy reading produces exactly one dominant reason per
 * credential. The corresponding policy and provider types are introduced
 * in later Phase-1a prompts.</p>
 */
public enum RehashReason {
  ALGORITHM_DEPRECATED,
  PROVIDER_DEPRECATED,
  POLICY_VERSION_OUTDATED,
  PARAMETERS_OUTDATED,
  PEPPER_KEY_ROTATED,
  FORMAT_VERSION_OUTDATED
}
