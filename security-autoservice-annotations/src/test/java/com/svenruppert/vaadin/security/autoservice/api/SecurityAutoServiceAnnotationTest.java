/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.vaadin.security.autoservice.api;

import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SecurityAutoServiceAnnotationTest {

  @Test
  void annotationHasSourceRetention() {
    Retention retention = SecurityAutoService.class.getAnnotation(Retention.class);
    assertNotNull(retention, "@Retention must be present");
    assertEquals(RetentionPolicy.SOURCE, retention.value(),
        "Annotation must be SOURCE retention to leave no class-file trace");
  }

  @Test
  void annotationTargetsType() {
    Target target = SecurityAutoService.class.getAnnotation(Target.class);
    assertNotNull(target, "@Target must be present");
    assertArrayEquals(new ElementType[]{ElementType.TYPE}, target.value(),
        "@Target must be TYPE only");
  }
}
