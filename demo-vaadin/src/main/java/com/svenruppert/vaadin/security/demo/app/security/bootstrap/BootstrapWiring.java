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
package com.svenruppert.vaadin.security.demo.app.security.bootstrap;

import com.svenruppert.vaadin.security.bootstrap.BootstrapConfiguration;
import com.svenruppert.vaadin.security.bootstrap.BootstrapMode;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStartup;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStateService;
import com.svenruppert.vaadin.security.bootstrap.BootstrapTokenGenerator;
import com.svenruppert.vaadin.security.bootstrap.BootstrapTokenOutput;
import com.svenruppert.vaadin.security.bootstrap.BootstrapTokenStore;
import com.svenruppert.vaadin.security.bootstrap.ConsoleBootstrapTokenOutput;
import com.svenruppert.vaadin.security.bootstrap.FileBootstrapTokenOutput;
import com.svenruppert.vaadin.security.bootstrap.FileBootstrapTokenStore;
import com.svenruppert.vaadin.security.bootstrap.InMemoryBootstrapTokenStore;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminBootstrapService;
import com.svenruppert.vaadin.security.bootstrap.MinimumLengthPasswordPolicy;
import com.svenruppert.vaadin.security.demo.app.security.model.UserStorage;

import java.nio.file.Path;

/**
 * Lazy holder for the bootstrap services used by {@code SetupView}.
 * <p>
 * The bootstrap mode is controlled by system properties (matching the
 * REST demo):
 * <ul>
 *   <li>{@code security.bootstrap.mode} = {@code DISABLED} (default) /
 *       {@code TRANSIENT_CONSOLE} / {@code PERSISTENT_FILE}</li>
 *   <li>{@code security.bootstrap.token.file} = path used by
 *       {@code PERSISTENT_FILE}</li>
 * </ul>
 */
public final class BootstrapWiring {

  private static volatile BootstrapWiring current;

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;

  private BootstrapWiring(BootstrapStateService state, InitialAdminBootstrapService service) {
    this.stateService = state;
    this.bootstrapService = service;
  }

  public BootstrapStateService stateService() {
    return stateService;
  }

  public InitialAdminBootstrapService bootstrapService() {
    return bootstrapService;
  }

  public static BootstrapWiring instance() {
    BootstrapWiring local = current;
    if (local != null) return local;
    synchronized (BootstrapWiring.class) {
      if (current == null) current = build();
      return current;
    }
  }

  private static BootstrapWiring build() {
    BootstrapConfiguration config = readConfiguration();
    if (config.mode() != BootstrapMode.DISABLED) {
      UserStorage.enableBootstrapMode();
    }
    VaadinAdministratorAccountStore adminStore = new VaadinAdministratorAccountStore();
    BootstrapStateService state = new BootstrapStateService(adminStore, config.mode());
    BootstrapTokenStore tokenStore = config.mode() == BootstrapMode.PERSISTENT_FILE
        ? new FileBootstrapTokenStore(config.tokenFilePath())
        : new InMemoryBootstrapTokenStore();
    BootstrapTokenOutput output = switch (config.mode()) {
      case PERSISTENT_FILE -> new FileBootstrapTokenOutput();
      case TRANSIENT_CONSOLE -> new ConsoleBootstrapTokenOutput("Open /setup to create the first administrator.");
      case DISABLED -> (token, configuration) -> {
        // no-op
      };
    };
    BootstrapStartup.initializeIfRequired(
        state, tokenStore, new BootstrapTokenGenerator(), output, config);
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokenStore, adminStore, UserStorage.passwordHasher(),
        new MinimumLengthPasswordPolicy(8),
        config.tokenValidity(), java.time.Clock.systemUTC());
    return new BootstrapWiring(state, service);
  }

  private static BootstrapConfiguration readConfiguration() {
    // Demo default: TRANSIENT_CONSOLE so the Vaadin demo "just works" when the
    // admin user is absent. Override with -Dsecurity.bootstrap.mode=DISABLED or
    // env SECURITY_BOOTSTRAP_MODE=DISABLED to turn it off, or PERSISTENT_FILE
    // to write the token to a file.
    String modeValue = firstNonBlank(
        System.getProperty("security.bootstrap.mode"),
        System.getenv("SECURITY_BOOTSTRAP_MODE"));
    if (modeValue == null) modeValue = "TRANSIENT_CONSOLE";
    BootstrapMode mode;
    try {
      mode = BootstrapMode.valueOf(modeValue.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      mode = BootstrapMode.TRANSIENT_CONSOLE;
    }
    return switch (mode) {
      case DISABLED -> BootstrapConfiguration.disabled();
      case TRANSIENT_CONSOLE -> BootstrapConfiguration.transientConsole();
      case PERSISTENT_FILE -> {
        String path = firstNonBlank(
            System.getProperty("security.bootstrap.token.file"),
            System.getenv("SECURITY_BOOTSTRAP_TOKEN_FILE"));
        if (path == null) path = "./data/bootstrap.token";
        yield BootstrapConfiguration.persistent(Path.of(path));
      }
    };
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) return a;
    if (b != null && !b.isBlank()) return b;
    return null;
  }
}
