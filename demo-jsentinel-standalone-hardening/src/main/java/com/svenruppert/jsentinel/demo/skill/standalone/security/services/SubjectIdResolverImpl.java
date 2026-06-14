package com.svenruppert.jsentinel.demo.skill.standalone.security.services;

import com.svenruppert.jsentinel.authorization.api.SubjectIdResolver;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.demo.skill.standalone.security.model.User;

/**
 * Maps the application's typed {@link User} to the framework's
 * {@link SubjectId} key. Required for Phase-4c drift detection: the
 * {@code LoginView} needs to derive a stable {@code SubjectId} from
 * the just-authenticated subject to capture a
 * {@code JSentinelVersion} snapshot, and the
 * {@code VersionBumper} needs the same mapping to increment that
 * key on role changes.
 *
 * <p>SPI-registered via
 * {@code META-INF/services/com.svenruppert.jsentinel.authorization.api.SubjectIdResolver}.
 */
public final class SubjectIdResolverImpl implements SubjectIdResolver<User> {

  @Override
  public SubjectId resolve(User subject) {
    return SubjectId.of(String.valueOf(subject.id()));
  }

  @Override
  public TenantId tenantFor(User subject) {
    return TenantId.DEFAULT;
  }
}
