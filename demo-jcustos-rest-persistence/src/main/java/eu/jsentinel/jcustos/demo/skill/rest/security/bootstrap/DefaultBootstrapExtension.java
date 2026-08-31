package eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap;

import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;

/**
 * Layer-1 defaults: in-memory ring buffer for audit, PBKDF2 for
 * password hashing. Registered via
 * {@code META-INF/services/eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapExtension}.
 */
public final class DefaultBootstrapExtension implements BootstrapExtension {

  @Override
  public void contributeAudit(AuditBootstrap a) {
    a.ringBuffer(256).logging();
  }

  @Override
  public void contributeCredentials(CredentialBootstrap c) {
    c.hashing(PasswordHashingServices.defaults());
  }

  @Override
  public int order() {
    return 0;
  }
}
