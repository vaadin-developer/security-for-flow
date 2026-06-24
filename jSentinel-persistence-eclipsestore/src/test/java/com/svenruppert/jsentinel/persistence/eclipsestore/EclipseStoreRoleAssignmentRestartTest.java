/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.persistence.eclipsestore;

import com.svenruppert.jsentinel.authorization.api.roles.RoleAssignmentKey;
import com.svenruppert.jsentinel.authorization.api.roles.RoleAssignmentStore;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Restart-persistence tests for the role-assignment store (R002). {@code
 * assignRole} / {@code revokeRole} mutate a nested role set in place, so a
 * close/reopen is the only way to catch a {@code store(parentMap)} that fails to
 * persist the nested mutation — a silent privilege-revert across restart.
 */
@DisplayName("EclipseStoreRoleAssignmentStore — survives restart (R002)")
class EclipseStoreRoleAssignmentRestartTest {

  @TempDir
  Path tempDir;

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final RoleName EDITOR = new RoleName("EDITOR");
  private static final RoleAssignmentKey ALICE =
      new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId("alice"));

  @Test
  @DisplayName("a second assigned role survives a close/reopen")
  void assignedRolesSurviveRestart() {
    try (EclipseStoreJSentinelStorage storage =
             EclipseStoreJSentinelStorage.openAt(tempDir)) {
      RoleAssignmentStore store = storage.roleAssignmentStore();
      store.assignRole(ALICE, ADMIN);
      store.assignRole(ALICE, EDITOR); // mutates the already-persisted set
      assertEquals(Set.of(ADMIN, EDITOR), store.findRoles(ALICE));
    }
    try (EclipseStoreJSentinelStorage reopened =
             EclipseStoreJSentinelStorage.openAt(tempDir)) {
      assertEquals(Set.of(ADMIN, EDITOR),
          reopened.roleAssignmentStore().findRoles(ALICE),
          "both assigned roles must survive a restart");
    }
  }

  @Test
  @DisplayName("an in-place revoke survives a close/reopen")
  void revokedRoleSurvivesRestart() {
    try (EclipseStoreJSentinelStorage storage =
             EclipseStoreJSentinelStorage.openAt(tempDir)) {
      RoleAssignmentStore store = storage.roleAssignmentStore();
      store.assignRole(ALICE, ADMIN);
      store.assignRole(ALICE, EDITOR);
      assertTrue(store.revokeRole(ALICE, EDITOR)); // in-place remove, ADMIN stays
      assertEquals(Set.of(ADMIN), store.findRoles(ALICE));
    }
    try (EclipseStoreJSentinelStorage reopened =
             EclipseStoreJSentinelStorage.openAt(tempDir)) {
      assertEquals(Set.of(ADMIN),
          reopened.roleAssignmentStore().findRoles(ALICE),
          "the revoke must survive a restart — EDITOR gone, ADMIN kept");
    }
  }
}
