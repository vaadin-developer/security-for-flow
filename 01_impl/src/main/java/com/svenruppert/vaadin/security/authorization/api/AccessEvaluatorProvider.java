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
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.dependencies.core.serviceprovider.ServiceProvider;

/**
 * @deprecated AccessEvaluators are resolved via {@code @NavigationAnnotation}
 *     and the Vaadin instantiator. Direct SPI lookup is not needed.
 */
@Deprecated(since = "0.50.0", forRemoval = false)
public class AccessEvaluatorProvider
        implements ServiceProvider<AccessEvaluator> {
    @Override
    public Class<AccessEvaluator> serviceInterface() {
        return AccessEvaluator.class;
    }
}

