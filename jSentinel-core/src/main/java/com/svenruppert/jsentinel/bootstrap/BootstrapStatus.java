/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.bootstrap;

import java.util.Objects;

/**
 * Adapter-neutral, leak-safe view of the bootstrap state.
 * <p>
 * Intentionally never carries the bootstrap token value.
 *
 * @param bootstrapRequired {@code true} while the system is uninitialized
 *                          and the bootstrap mechanism is enabled
 * @param mode              currently configured bootstrap mode
 */
public record BootstrapStatus(boolean bootstrapRequired, BootstrapMode mode) {

  public BootstrapStatus {
    Objects.requireNonNull(mode, "mode must not be null");
  }

  public static BootstrapStatus from(BootstrapStateService stateService) {
    return new BootstrapStatus(stateService.bootstrapRequired(), stateService.mode());
  }
}
