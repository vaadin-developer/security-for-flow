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

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;
import java.util.Set;

/**
 * V00.74 compile-time wrapper generator for {@code @PropagateToken}.
 *
 * <p>Prompt 012 ships the skeleton — the processor declares
 * {@code @PropagateToken} as its supported annotation type but
 * performs no generation. Prompt 013 lands the real
 * {@code <Type>Propagating} generation logic; Prompt 014 lands the
 * wrapper-index {@code kind} column write path.
 *
 * @since 00.74.00
 */
@SupportedAnnotationTypes("com.svenruppert.jsentinel.annotations.PropagateToken")
@SupportedSourceVersion(SourceVersion.RELEASE_26)
public final class PropagateTokenProcessor extends AbstractProcessor {

  /** Required by the {@link AbstractProcessor} contract. */
  public PropagateTokenProcessor() {
  }

  @Override
  public boolean process(Set<? extends TypeElement> annotations,
                         RoundEnvironment roundEnv) {
    // Prompt 012: skeleton no-op. Prompt 013 emits <Type>Propagating
    // sources here.
    return false;
  }
}
