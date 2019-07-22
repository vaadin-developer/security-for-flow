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
