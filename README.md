
<center>
<a href="https://vaadin.com">
 <img src="https://vaadin.com/images/hero-reindeer.svg" width="200" height="200"  alt="Vaadin Logo"/></a>
</center>


#Vaadin Flow Security
How to build different Security Aspects into a Flow Application.

## Module flow-security
This module contains al generic parts that could be shared between projects.


## Module flow-security-test
This module is a demo app using the module **flow-security**

## Different possibilities
### Basic LoginView
This LoginView will have basic elements you need for an authorization.
What ever is part of the base LoginView, it will never be the right thing.
How to extend this, have a look into the custom implementation
in the the demo app. The class name is **MyLoginView**. 

### Roles and Permissions
Every System will have its own way to describe Roles and Permission.
The only thing I assume here is, that for example a Role will have a name.

```java
public final class RoleName
    extends Single<String> {
  public RoleName(String s) {
    super(s);
  }
  public String roleName() {
    return getT1();
  }
}
```

The interface ```HasRoles``` will be used inside the generic implementation to get access to this information.
The custom part will be responsible to map from the existing system to this Interfaces.
The demo app will show this inside the class ```MyAuthorizationService```.



* Login
* Free View and Restricted Views
* MenuBar based on User-Roles/Rights
* Components are visible based on User-Roles/Rights
* 



## How to use it in your project
In this section I will describe the steps that are needed to use this in your project.
If you want to have a starter app that is always containing this and some other features like 
I18N, have a look at the following: **XXXXX**

For every step I will give you the name of the corresponding implementation inside the demo app.

* Define the class that will hold your user informations inside a session: **MyUSer**
* Access to your DataSource including the mapping: **UserStorage** 
* Define your Role enum: **AuthorizationRole**
* Define the Annotation you want to use in your app to declare the role: **VisibleFor**
* extend the class RoleAccessEvaluator: **MyRoleAccessEvaluator**
* implement the AuthorizationService: **MyAuthenticationService**



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
