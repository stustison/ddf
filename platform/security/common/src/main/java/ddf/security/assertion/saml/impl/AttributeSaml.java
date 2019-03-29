package ddf.security.assertion.saml.impl;

import ddf.security.assertion.Attribute;
import java.util.Collections;
import java.util.List;

public class AttributeSaml implements Attribute {

  private String name;

  private String nameFormat;

  private List<String> values;

  @Override
  public String getName() {
    return name;
  }

  @Override
  public void setName(String name) {
    this.name = name;
  }

  @Override
  public String getNameFormat() {
    return nameFormat;
  }

  @Override
  public void setNameFormat(String nameFormat) {
    this.nameFormat = nameFormat;
  }

  @Override
  public List<String> getValues() {
    return Collections.unmodifiableList(values);
  }

  @Override
  public void setValues(List<String> values) {
    this.values = values;
  }

  @Override
  public void addValue(String value) {
    this.values.add(value);
  }
}
