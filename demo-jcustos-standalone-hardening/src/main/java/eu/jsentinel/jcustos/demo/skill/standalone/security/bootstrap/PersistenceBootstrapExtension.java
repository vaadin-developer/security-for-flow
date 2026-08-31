package eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap;

import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage;

/**
 * Persistence-layer extension for the standalone CLI. Contributes
 * Eclipse-Store storeBacked audit + session stores; eagerly opens
 * the storage backend and triggers
 * {@link BootstrapWiring#instance()} so the bootstrap token is ready
 * before the CLI prompts for setup.
 */
public final class PersistenceBootstrapExtension implements BootstrapExtension {

  private static final EclipseStoreJCustosStorage STORAGE;

  static {
    STORAGE = JCustosStorageProvider.storage();
    BootstrapWiring.instance();
  }

  @Override
  public void contributeAudit(AuditBootstrap a) {
    a.storeBacked(STORAGE.auditEventStore()).logging();
  }

  @Override
  public void contributeSessions(SessionBootstrap s) {
    s.storeBacked(STORAGE.sessionStore());
  }

  @Override
  public int order() {
    return 10;
  }
}
