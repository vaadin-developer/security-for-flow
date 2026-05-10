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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authorization.api.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptContext;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptDecision;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.demo.restclient.backend.BackendClientProvider;
import com.svenruppert.vaadin.security.demo.restclient.backend.Credentials;
import com.svenruppert.vaadin.security.demo.restclient.backend.LoginResult;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteUser;
import com.vaadin.flow.server.VaadinRequest;

/**
 * SPI-loaded {@link AuthenticationService} that delegates the credential
 * check to the demo-rest backend via {@link BackendClientProvider}.
 * <p>
 * On a successful login the returned token + {@link RemoteUser} are
 * stored in {@link ClientSecurityContext} so subsequent calls
 * ({@code loadSubject}, {@code SubjectStore.currentSubject(...)}) return
 * them without another round-trip.
 * <p>
 * Repeated failures are throttled locally via the
 * {@link LoginAttemptPolicy} resolved through
 * {@link SecurityServiceResolver}, so a brute-force attempt stops at the
 * Vaadin layer before issuing yet another HTTP call against the backend.
 */
public class RestBackedAuthenticationService
    implements AuthenticationService<Credentials, RemoteUser> {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }

    LoginAttemptPolicy policy = SecurityServiceResolver.loginAttemptPolicy();
    LoginAttemptContext attempt = LoginAttemptContext.now(
        credentials.username(), currentClientAddress(), null);

    LoginAttemptDecision decision = policy.beforeAttempt(attempt);
    if (decision instanceof LoginAttemptDecision.LockedOut) {
      return false;
    }

    LoginResult result = BackendClientProvider.client().login(credentials);
    if (result instanceof LoginResult.Authenticated(String token, RemoteUser user)) {
      ClientSecurityContext.setActiveLogin(token, user);
      policy.recordSuccess(attempt);
      return true;
    }
    policy.recordFailure(attempt);
    return false;
  }

  @Override
  public RemoteUser loadSubject(Credentials credentials) {
    return ClientSecurityContext.user().orElse(null);
  }

  @Override
  public Class<RemoteUser> subjectType() {
    return RemoteUser.class;
  }

  private static String currentClientAddress() {
    try {
      VaadinRequest request = VaadinRequest.getCurrent();
      return request == null ? null : request.getRemoteAddr();
    } catch (RuntimeException ignored) {
      return null;
    }
  }
}
