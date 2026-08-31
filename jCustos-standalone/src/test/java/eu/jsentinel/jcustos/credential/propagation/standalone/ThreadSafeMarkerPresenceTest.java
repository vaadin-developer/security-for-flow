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

import eu.jsentinel.jcustos.credential.propagation.ThreadSafeTokenCredentialStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Standalone default store carries ThreadSafeTokenCredentialStore marker")
class ThreadSafeMarkerPresenceTest {

  @Test
  @DisplayName("ThreadLocalTokenCredentialStore is marked thread-safe")
  void markerPresent() {
    assertTrue(new ThreadLocalTokenCredentialStore() instanceof ThreadSafeTokenCredentialStore,
        "Standalone ThreadLocalTokenCredentialStore must carry the ThreadSafeTokenCredentialStore marker");
  }
}
