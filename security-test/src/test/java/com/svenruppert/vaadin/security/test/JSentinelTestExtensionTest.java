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
package com.svenruppert.vaadin.security.test;

import com.svenruppert.vaadin.security.audit.NoopJSentinelAuditService;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class JSentinelTestExtensionTest {

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("beforeEach clears a previously cached non-fallback service")
  void beforeEachClearsCache() {
    RecordingAuditSink custom = new RecordingAuditSink();
    JSentinelServiceResolver.setJSentinelAuditService(custom);
    assertSame(custom, JSentinelServiceResolver.securityAuditService());

    new JSentinelTestExtension().beforeEach(null);

    assertNotSame(custom, JSentinelServiceResolver.securityAuditService());
    assertSame(NoopJSentinelAuditService.INSTANCE,
        JSentinelServiceResolver.securityAuditService());
  }

  @Test
  @DisplayName("afterEach clears a previously cached non-fallback service")
  void afterEachClearsCache() {
    RecordingAuditSink custom = new RecordingAuditSink();
    JSentinelServiceResolver.setJSentinelAuditService(custom);

    new JSentinelTestExtension().afterEach(null);

    assertSame(NoopJSentinelAuditService.INSTANCE,
        JSentinelServiceResolver.securityAuditService());
  }
}
