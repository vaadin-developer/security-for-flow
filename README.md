
<center>
<a href="https://vaadin.com">
 <img src="https://vaadin.com/images/hero-reindeer.svg" width="200" height="200"  alt="Vaadin Logo"/></a>
</center>


# POC Vaadin Flow Security
How to build different Security Aspects into a Flow Application.

* Login
* Free View and Restricted Views
* MenuBar based on User-Roles/Rights
* Components are visible based on User-Roles/Rights
* 







## Example/Pseudo Code

```java
@VisibleTo(UserRole.Admin, UserRole.Nerd)
public class MyView extends Composite<Div>{}
```

```java
@VisibleToDynamic(UserRole.Admin, UserRole.Nerd)
public class MyView extends Composite<Div>{}
```





## Supported JDK
This example is running from JDK8 up to JDK13

## target of this project
The target of this project is a minimal rampup time for a first hello world.
Why we need one more HelloWorld? Well, the answer is quite easy. 
If you have to try something out, or you want to make a small POC to present something,
there is no time and budget to create a demo project.
You don´t want to copy paste all small things together.
Here you will get a Nano-Project that will give you all in a second.

Clone the repo and start editing the file ```NanoVaadinOnKotlin.kt```.
Nothing more. 

## How does it work?
Internally it will ramp up a Jetty. If you want to see how this is done, have a look inside
the class ```CoreUIService```.

## How a developer can use this
You as a developer can use it like it is shown in the demo folder inside the src path.

```kotlin
fun main() {
  CoreUIService().startup()
}
```


```kotlin
@Route("")
class VaadinApp : Composite<Div>(), HasLogger {

  private val btnClickMe = Button("click me")
  private val lbClickCount = Span("0")
  private val layout = VerticalLayout(btnClickMe, lbClickCount)

  private var clickcount = 0

  init {
    btnClickMe.setId(BTN_CLICK_ME)
    btnClickMe.addClickListener { event -> lbClickCount.text = (++clickcount).toString() }

    lbClickCount.setId(LB_CLICK_COUNT)

    logger().info("and now..  setting the main content.. ")
    content.add(layout)
  }

  companion object {

    val BTN_CLICK_ME = "btn-click-me"
    val LB_CLICK_COUNT = "lb-click-count"
  }
}
```

Happy Coding.

if you have any questions: ping me on Twitter [https://twitter.com/SvenRuppert](https://twitter.com/SvenRuppert)
or via mail.
