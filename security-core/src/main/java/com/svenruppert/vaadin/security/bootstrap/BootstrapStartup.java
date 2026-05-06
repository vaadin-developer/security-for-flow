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
package com.svenruppert.vaadin.security.bootstrap;

/**
 * One-shot startup orchestrator. Call this once during server boot.
 * <p>
 * If bootstrap is required and no token is currently stored, generates a
 * fresh token, persists it, and emits the operator-facing setup banner via
 * the configured {@link BootstrapTokenOutput}. If a token already exists
 * (persistent mode after restart), it is reused so the user can resume the
 * setup.
 */
public final class BootstrapStartup {

  private BootstrapStartup() {
  }

  public static void initializeIfRequired(
      BootstrapStateService stateService,
      BootstrapTokenStore tokenStore,
      BootstrapTokenGenerator generator,
      BootstrapTokenOutput output,
      BootstrapConfiguration configuration) {
    if (!stateService.bootstrapRequired()) return;
    BootstrapToken token = tokenStore.load().orElseGet(() -> {
      BootstrapToken fresh = generator.generate();
      tokenStore.save(fresh);
      return fresh;
    });
    output.emit(token, configuration);
  }
}
