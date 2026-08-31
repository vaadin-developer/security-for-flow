package eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap;

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.BootstrapStartup;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateService;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenGenerator;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.InitialAdminBootstrapService;
import eu.jsentinel.jcustos.bootstrap.MinimumLengthPasswordPolicy;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;

import java.nio.file.Path;
import java.time.Clock;

/**
 * REST-side first-admin bootstrap. Same wiring as the Vaadin variant
 * — only the way it gets invoked differs (the layer-2
 * {@code RestServer} template calls {@link #instance()} during
 * startup; in the Vaadin variant the bootstrap was eagerly created
 * by the {@code VaadinServiceInitListener}).
 */
public final class BootstrapWiring {

  public static final BootstrapMode DEFAULT_MODE = BootstrapMode.PERSISTENT_FILE;
  public static final Path DEFAULT_TOKEN_FILE = Path.of("./data/jcustos-rest-persistence/bootstrap.token");

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
