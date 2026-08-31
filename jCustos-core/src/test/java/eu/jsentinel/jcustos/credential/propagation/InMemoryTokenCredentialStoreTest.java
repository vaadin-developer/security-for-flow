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
package eu.jsentinel.jcustos.credential.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryTokenCredentialStore — Store contract")
class InMemoryTokenCredentialStoreTest {

  @Test
  @DisplayName("Fresh store is empty")
  void freshIsEmpty() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("bind followed by current returns the bound credential")
  void bindThenCurrent() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    BearerToken token = new BearerToken("abc");
    store.bind(token);
    assertEquals(token, store.current().orElseThrow());
  }

  @Test
  @DisplayName("Re-bind replaces the previous entry")
  void rebindReplaces() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    store.bind(new BearerToken("first"));
    store.bind(new BearerToken("second"));
    assertEquals("second", ((BearerToken) store.current().orElseThrow()).value());
  }

  @Test
  @DisplayName("clear() returns the store to the empty state")
  void clearEmpties() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    store.bind(new BearerToken("abc"));
    store.clear();
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("clear() is idempotent")
  void clearIdempotent() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    store.clear();
    store.clear();
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("bind(null) throws NullPointerException")
  void bindNullRejected() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    assertThrows(NullPointerException.class, () -> store.bind(null));
  }
}
