/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation.standalone;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.standalone.StandaloneLoginFlow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StandaloneLoginFlow — bindToken + logout clears store")
class StandaloneLoginFlowBindTokenTest {

  private final TokenCredentialStore store = new ThreadLocalTokenCredentialStore();
  private final StubAuth auth = new StubAuth();

  @BeforeEach
  void setup() {
    JCustosServiceResolver.setTokenCredentialStore(store);
  }

  @AfterEach
  void cleanup() {
    store.clear();
    JCustosServiceResolver.setTokenCredentialStore(null);
  }

  @Test
  @DisplayName("bindToken sets the credential into the resolver-resolved store")
  void bindTokenSetsCredential() {
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.systemUTC());
    flow.bindToken(new BearerToken("abc"));
    assertEquals("abc", ((BearerToken) store.current().orElseThrow()).value());
  }

  @Test
  @DisplayName("logout() also clears the propagation slot")
  void logoutClearsStore() {
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.systemUTC());
    flow.bindToken(new BearerToken("abc"));
    flow.logout();
    assertTrue(store.current().isEmpty());
  }

  private static final class StubAuth implements AuthenticationService<String, String> {
    @Override public boolean checkCredentials(String credentials) { return false; }
    @Override public String loadSubject(String credentials) { return credentials; }
    @Override public Class<String> subjectType() { return String.class; }
  }
}
