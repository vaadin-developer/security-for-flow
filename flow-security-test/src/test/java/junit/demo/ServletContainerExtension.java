/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package junit.demo;

import demo.CoreUIService;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.stagemonitor.core.Stagemonitor;

import static org.junit.jupiter.api.extension.ExtensionContext.Namespace.GLOBAL;

public class ServletContainerExtension
    implements BeforeEachCallback, AfterEachCallback {

  public static final String CORE_SERVICE = "core-service";

  @Override
  public void beforeEach(ExtensionContext extensionContext) throws Exception {
    Stagemonitor.init();
    final CoreUIService coreUIService = new CoreUIService();
    coreUIService.startup();
    extensionContext.getStore(GLOBAL).put(CORE_SERVICE, coreUIService);
  }


  @Override
  public void afterEach(ExtensionContext extensionContext) throws Exception {
    final CoreUIService coreUIService = extensionContext.getStore(GLOBAL)
                                                        .get(CORE_SERVICE, CoreUIService.class);
    coreUIService.stop();
  }
}
