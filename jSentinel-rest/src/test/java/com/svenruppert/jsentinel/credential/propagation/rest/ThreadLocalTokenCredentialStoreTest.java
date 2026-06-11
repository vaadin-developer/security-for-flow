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
package com.svenruppert.jsentinel.credential.propagation.rest;

import com.svenruppert.jsentinel.credential.propagation.BearerToken;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ThreadLocalTokenCredentialStore (REST)")
class ThreadLocalTokenCredentialStoreTest {

  private final TokenCredentialStore store = new ThreadLocalTokenCredentialStore();

  @AfterEach
  void cleanup() { store.clear(); }

  @Test
  @DisplayName("bind + current round-trip on a single thread")
  void roundTrip() {
    store.bind(new BearerToken("abc"));
    assertEquals("abc", ((BearerToken) store.current().orElseThrow()).value());
    store.clear();
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("Two threads see independent slots")
  void threadIsolation() throws InterruptedException {
    store.bind(new BearerToken("main"));
    AtomicReference<Optional<?>> other = new AtomicReference<>();
    CountDownLatch latch = new CountDownLatch(1);
    Thread worker = new Thread(() -> {
      other.set(store.current());
      latch.countDown();
    });
    worker.start();
    latch.await();
    worker.join();
    assertTrue(other.get().isEmpty(), "worker thread must not see main's slot");
    assertEquals("main", ((BearerToken) store.current().orElseThrow()).value());
  }
}
