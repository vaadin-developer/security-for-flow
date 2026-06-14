package com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.jsentinel.bootstrap.BootstrapConfiguration;
import com.svenruppert.jsentinel.bootstrap.BootstrapMode;
import com.svenruppert.jsentinel.bootstrap.BootstrapStartup;
import com.svenruppert.jsentinel.bootstrap.BootstrapStateService;
import com.svenruppert.jsentinel.bootstrap.BootstrapTokenGenerator;
import com.svenruppert.jsentinel.bootstrap.BootstrapTokenOutput;
import com.svenruppert.jsentinel.bootstrap.BootstrapTokenStore;
import com.svenruppert.jsentinel.bootstrap.FileBootstrapTokenOutput;
import com.svenruppert.jsentinel.bootstrap.FileBootstrapTokenStore;
import com.svenruppert.jsentinel.bootstrap.InitialAdminBootstrapService;
import com.svenruppert.jsentinel.bootstrap.MinimumLengthPasswordPolicy;
import com.svenruppert.jsentinel.credential.password.PasswordHashingServices;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.UserDirectoryProvider;

import java.nio.file.Path;
import java.time.Clock;

/**
 * Wires the first-admin bootstrap flow.
 *
 * <p>Lazy singleton: the first call constructs the chain once and
 * caches it. Layers:
 *
 * <ol>
 *   <li>{@link BootstrapStateService} reads
 *       {@code AdministratorAccountStore.hasAnyAdministrator()} to
 *       decide whether the system is uninitialised.</li>
 *   <li>{@link BootstrapStartup#initializeIfRequired} generates a
 *       one-time token on first start, persists it to
 *       {@code ./data/jsentinel-vaadin-persistence/bootstrap.token} and prints both the path and
 *       the token to stdout.</li>
 *   <li>{@link InitialAdminBootstrapService} validates the token from
 *       the {@code SetupView} form and creates the admin via the
 *       {@link AdministratorAccountStoreImpl} adapter.</li>
 * </ol>
 *
 * <p>The token file lives at {@code ./data/jsentinel-vaadin-persistence/bootstrap.token} —
 * delete it (and any admin row in the persistent storage) to force
 * a re-bootstrap.
 */
public final class BootstrapWiring {

  public static final BootstrapMode DEFAULT_MODE = BootstrapMode.PERSISTENT_FILE;
  public static final Path DEFAULT_TOKEN_FILE = Path.of("./data/jsentinel-vaadin-persistence/bootstrap.token");

  private static volatile BootstrapWiring current;

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;

  private BootstrapWiring(BootstrapStateService stateService,
                          InitialAdminBootstrapService bootstrapService) {
    this.stateService = stateService;
    this.bootstrapService = bootstrapService;
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
    BootstrapConfiguration config = new BootstrapConfiguration(
        DEFAULT_MODE, DEFAULT_TOKEN_FILE, BootstrapConfiguration.DEFAULT_VALIDITY);
    AdministratorAccountStoreImpl adminStore =
        new AdministratorAccountStoreImpl(UserDirectoryProvider.directory());
    BootstrapStateService state = new BootstrapStateService(adminStore, config.mode());
    BootstrapTokenStore tokenStore = new FileBootstrapTokenStore(config.tokenFilePath());
    BootstrapTokenOutput output = new FileBootstrapTokenOutput();
    BootstrapStartup.initializeIfRequired(
        state, tokenStore, new BootstrapTokenGenerator(), output, config);
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokenStore, adminStore,
        PasswordHashingServices.defaults(),
        new MinimumLengthPasswordPolicy(8),
        config.tokenValidity(), Clock.systemUTC());
    return new BootstrapWiring(state, service);
  }
}
