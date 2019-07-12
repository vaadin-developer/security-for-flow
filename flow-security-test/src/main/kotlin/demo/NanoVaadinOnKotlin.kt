package demo

import org.stagemonitor.core.Stagemonitor


fun main() {
  Stagemonitor.init();
  CoreUIService().startup()
}

