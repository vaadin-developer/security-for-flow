package demo

import org.rapidpm.vaadin.nano.CoreUIService
import org.stagemonitor.core.Stagemonitor


fun main() {
  Stagemonitor.init();
  CoreUIService().startup()
}

//@Route("")
//class VaadinApp : Composite<Div>(), HasLogger {
//
//  private val btnClickMe = Button("click me")
//  private val lbClickCount = Span("0")
//  private val layout = VerticalLayout(btnClickMe, lbClickCount)
//
//  private var clickcount = 0
//
//  init {
//    btnClickMe.setId(BTN_CLICK_ME)
//    btnClickMe.addClickListener { event -> lbClickCount.text = (++clickcount).toString() }
//
//    lbClickCount.setId(LB_CLICK_COUNT)
//
//    logger().info("and now..  setting the main content.. ")
//    content.add(layout)
//  }
//
//  companion object {
//
//    val BTN_CLICK_ME = "btn-click-me"
//    val LB_CLICK_COUNT = "lb-click-count"
//  }
//}