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
package com.svenruppert.jsentinel.identity.oidc;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.oidc.api.BackChannelLogoutOutcome;
import com.svenruppert.jsentinel.oidc.api.BackChannelLogoutToken;
import com.svenruppert.jsentinel.oidc.api.LogoutTokenValidator;
import com.svenruppert.jsentinel.oidc.api.SessionRegistry;

import java.util.Objects;
import java.util.Set;

/**
 * Receives an OIDC Back-Channel Logout request (V00.79): validates the posted
 * {@code logout_token} with a {@link LogoutTokenValidator}, then terminates the matching
 * RP sessions via the {@link SessionRegistry}. Pure token-in / outcome-out — it never
 * dereferences any URL from the token, so it introduces no SSRF (OIDC BCL 1.0 §2.6).
 * The outcome maps to the §2.7 HTTP response (200 Accepted / 400 Rejected).
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public final class BackChannelLogoutReceiver {

  private final LogoutTokenValidator validator;
  private final SessionRegistry sessionRegistry;

  public BackChannelLogoutReceiver(LogoutTokenValidator validator, SessionRegistry sessionRegistry) {
    this.validator = Objects.requireNonNull(validator, "validator");
    this.sessionRegistry = Objects.requireNonNull(sessionRegistry, "sessionRegistry");
  }

  public BackChannelLogoutOutcome receive(String logoutToken) {
    Objects.requireNonNull(logoutToken, "logoutToken");
    return validator.validate(logoutToken).fold(
        token -> new BackChannelLogoutOutcome.Accepted(terminate(token)),
        BackChannelLogoutOutcome.Rejected::new);
  }

  private Set<String> terminate(BackChannelLogoutToken token) {
    return sessionRegistry.terminate(token.issuer(), token.subject(), token.sid());
  }
}
