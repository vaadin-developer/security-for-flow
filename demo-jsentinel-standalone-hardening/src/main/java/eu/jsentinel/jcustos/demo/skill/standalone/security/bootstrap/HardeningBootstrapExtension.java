package eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.credential.password.bouncycastle.BouncyCastleHashingServices;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;
import eu.jsentinel.jcustos.session.JCustosVersionStore;

import java.util.Optional;

/**
 * Hardening-layer extension for the standalone CLI. Argon2id +
 * drift detection. Drift detection in single-session CLIs is
 * largely latent, but wiring it through {@code
 * BootstrapBuilder.apply(...)} keeps the surface uniform across all
 * three adapters.
 */
public final class HardeningBootstrapExtension implements BootstrapExtension {

  @Override
  public void contributeCredentials(CredentialBootstrap c) {
    c.hashing(BouncyCastleHashingServices.modern());
  }

  @Override
  public void contributeSessions(SessionBootstrap s) {
    Optional<JCustosVersionStore> versionStore =
        JCustosServiceResolver.findJCustosVersionStore();
    Optional<SubjectIdResolver<Object>> resolver =
        JCustosServiceResolver.findSubjectIdResolver();
    versionStore.ifPresent(s::securityVersion);
    resolver.ifPresent(s::subjectIdResolver);
  }

  @Override
  public int order() {
    return 20;
  }
}
