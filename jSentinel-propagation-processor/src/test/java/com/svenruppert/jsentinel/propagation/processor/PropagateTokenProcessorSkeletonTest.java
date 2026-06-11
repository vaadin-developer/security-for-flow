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
package com.svenruppert.jsentinel.propagation.processor;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PropagateTokenProcessor skeleton")
class PropagateTokenProcessorSkeletonTest {

  @Test
  @DisplayName("Declares @PropagateToken as its supported annotation type")
  void supportedAnnotationType() {
    PropagateTokenProcessor p = new PropagateTokenProcessor();
    assertTrue(p.getSupportedAnnotationTypes()
        .contains("com.svenruppert.jsentinel.annotations.PropagateToken"));
  }

  @Test
  @DisplayName("Targets Java 26 source level")
  void supportedSource() {
    PropagateTokenProcessor p = new PropagateTokenProcessor();
    assertEquals(SourceVersion.RELEASE_26, p.getSupportedSourceVersion());
  }

  @Test
  @DisplayName("Skeleton process(...) is a no-op and returns false")
  void processNoOp() {
    PropagateTokenProcessor p = new PropagateTokenProcessor();
    assertFalse(p.process(Collections.<TypeElement>emptySet(), null));
  }
}
