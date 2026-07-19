package com.svenruppert.jsentinel.audit.integrity.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Audit Integrity — Eclipse-Store persistence
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

import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainAppender;
import com.svenruppert.jsentinel.audit.integrity.verify.AuditChainVerificationResult;
import com.svenruppert.jsentinel.audit.integrity.verify.AuditIntegrityVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Audit chain across restarts — the Konzept goal-7 acceptance check")
class EclipseStoreAuditChainRestartTest {

  @TempDir
  Path tempDir;

  @Test
  @DisplayName("the chain survives close/reopen, keeps growing and re-verifies Valid")
  void chainSurvivesRestartAndReVerifies() {
    try (EclipseStoreAuditChainStorage first = EclipseStoreAuditChainStorage.openAt(tempDir)) {
      AuditChainAppender appender = new AuditChainAppender(first.chainStore());
      for (int i = 0; i < 3; i++) {
        appender.append("test/v1", ("pre-restart-" + i).getBytes(StandardCharsets.UTF_8));
      }
    }

    try (EclipseStoreAuditChainStorage second = EclipseStoreAuditChainStorage.openAt(tempDir)) {
      assertEquals(3, second.chainStore().size(), "the chain must survive the restart");
      AuditChainAppender appender = new AuditChainAppender(second.chainStore());
      for (int i = 0; i < 2; i++) {
        appender.append("test/v1", ("post-restart-" + i).getBytes(StandardCharsets.UTF_8));
      }

      AuditChainVerificationResult.Valid valid = assertInstanceOf(
          AuditChainVerificationResult.Valid.class,
          new AuditIntegrityVerifier().verify(second.chainStore()),
          "the pre+post-restart chain must verify as one intact chain");
      assertEquals(5, valid.entryCount());
      assertEquals(second.chainStore().head().orElseThrow().entryHash(), valid.headHash());
    }
  }

  @Test
  @DisplayName("a closed storage refuses further access and close is idempotent")
  void closedStorageRefuses() {
    EclipseStoreAuditChainStorage storage = EclipseStoreAuditChainStorage.openAt(tempDir);
    var store = storage.chainStore();
    storage.close();
    storage.close();
    assertThrows(IllegalStateException.class, store::size);
  }
}
