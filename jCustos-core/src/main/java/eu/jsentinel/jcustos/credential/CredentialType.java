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

package eu.jsentinel.jcustos.credential;


/**
 * Discriminating metadatum for the credential subsystem introduced with
 * version {@code 00.71.00}.
 *
 * <p>Phase 1a explicitly supports only {@link #PASSWORD}. Other credential
 * shapes (WebAuthn, TOTP, API tokens, remember-me cookies) are modelled
 * through dedicated services in later phases and are intentionally not
 * routed through the password hashing pipeline.</p>
 */
public enum CredentialType {
  PASSWORD
}
