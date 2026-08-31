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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StorageLayoutTest {

  @Test
  void default_hasExpectedSubdirs() {
    assertEquals("jcustos-store", StorageLayout.DEFAULT.frameworkSubdir());
    assertEquals("app-store", StorageLayout.DEFAULT.appSubdir());
  }

  @Test
  void nullFrameworkSubdir_throws() {
    assertThrows(NullPointerException.class,
        () -> new StorageLayout(null, "app"));
  }

  @Test
  void nullAppSubdir_throws() {
    assertThrows(NullPointerException.class,
        () -> new StorageLayout("framework", null));
  }

  @Test
  void blankFrameworkSubdir_throws() {
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new StorageLayout("   ", "app"));
    assertTrue(ex.getMessage().contains("frameworkSubdir"));
  }

  @Test
  void blankAppSubdir_throws() {
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new StorageLayout("framework", "   "));
    assertTrue(ex.getMessage().contains("appSubdir"));
  }

  @Test
  void forwardSlashInFrameworkSubdir_throws() {
    assertThrows(IllegalArgumentException.class,
        () -> new StorageLayout("foo/bar", "app"));
  }

  @Test
  void backslashInAppSubdir_throws() {
    assertThrows(IllegalArgumentException.class,
        () -> new StorageLayout("framework", "foo\\bar"));
  }

  @Test
  void nulByteInSubdir_throws() {
    assertThrows(IllegalArgumentException.class,
        () -> new StorageLayout("framework", "foo\0bar"));
  }

  @Test
  void identicalSubdirs_throws() {
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new StorageLayout("data", "data"));
    assertTrue(ex.getMessage().contains("storage-pair-subdir-collision"));
  }
}
