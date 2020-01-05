/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package demo;

import com.vaadin.flow.server.Constants;
import org.apache.commons.cli.ParseException;
import org.rapidpm.vaadin.nano.CoreUIServiceJava;

public class UIServiceJava extends CoreUIServiceJava {

  private UIServiceJava() {
  }

  public static void main(String[] args) throws ParseException {
    System.setProperty(Constants.SERVLET_PARAMETER_ENABLE_DEV_SERVER, "false");
    System.setProperty("vaadin.compatibilityMode", "false");
    System.setProperty("vaadin.productionMode", "true");
    CoreUIServiceJava uiService = new UIServiceJava().executeCLI(args);
    uiService.startup();
  }

}
