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
package com.svenruppert.vaadin.security.demo.app.views.workspaces;

import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

public class NerdWorkspace extends Composite<Div> {

  public NerdWorkspace() {
    HorizontalLayout badges = new HorizontalLayout();
    badges.setSpacing(true);
    Span adminBadge = new Span("ADMIN");
    adminBadge.getElement().getThemeList().add("badge error");
    Span nerdBadge = new Span("NERD");
    nerdBadge.getElement().getThemeList().add("badge contrast");
    badges.add(adminBadge, nerdBadge);

    H2 heading = new H2("Nerd Zone");

    HorizontalLayout header = new HorizontalLayout(VaadinIcon.CODE.create(), heading);
    header.setAlignItems(FlexComponent.Alignment.CENTER);
    header.setSpacing(true);

    Paragraph description = new Paragraph(
        "Advanced technical features and experimental tools. "
        + "Accessible to ADMIN and NERD roles — for those who appreciate the details.");

    VerticalLayout content = new VerticalLayout(badges, header, description);
    content.addClassNames("workspace", "workspace-nerd");
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");

    getContent().add(content);
  }
}
