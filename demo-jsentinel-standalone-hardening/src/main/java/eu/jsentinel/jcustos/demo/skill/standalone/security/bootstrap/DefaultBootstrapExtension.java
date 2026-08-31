package eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap;

import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;

/**
 * Layer-1 defaults: in-memory ring buffer for audit, PBKDF2 for
 * password hashing.
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
