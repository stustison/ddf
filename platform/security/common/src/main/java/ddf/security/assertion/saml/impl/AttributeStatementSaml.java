package ddf.security.assertion.saml.impl;

import ddf.security.assertion.Attribute;
import ddf.security.assertion.AttributeStatement;
import java.util.Collections;
import java.util.List;

public class AttributeStatementSaml implements AttributeStatement {

  private List<Attribute> attributes;

  @Override
  public List<Attribute> getAttributes() {
    return Collections.unmodifiableList(attributes);
  }

  @Override
  public void addAttribute(Attribute attribute) {
    this.attributes.add(attribute);
  }
}
