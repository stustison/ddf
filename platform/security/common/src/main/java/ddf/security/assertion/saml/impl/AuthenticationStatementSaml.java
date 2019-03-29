package ddf.security.assertion.saml.impl;

import ddf.security.assertion.AuthenticationStatement;
import org.joda.time.DateTime;

public class AuthenticationStatementSaml implements AuthenticationStatement {

  private DateTime authnInstant;

  private String sessionIndex;

  private DateTime sessionNotOnOrAfter;

  private String authnContextClassRef;

  @Override
  public DateTime getAuthnInstant() {
    return authnInstant;
  }

  @Override
  public void setAuthnInstant(DateTime authnInstant) {
    this.authnInstant = authnInstant;
  }

  @Override
  public String getSessionIndex() {
    return sessionIndex;
  }

  @Override
  public void setSessionIndex(String sessionIndex) {
    this.sessionIndex = sessionIndex;
  }

  @Override
  public DateTime getSessionNotOnOrAfter() {
    return sessionNotOnOrAfter;
  }

  @Override
  public void setSessionNotOnOrAfter(DateTime sessionNotOnOrAfter) {
    this.sessionNotOnOrAfter = sessionNotOnOrAfter;
  }

  @Override
  public String getAuthnContextClassRef() {
    return authnContextClassRef;
  }

  @Override
  public void setAuthnContextClassRef(String authnContextClassRef) {
    this.authnContextClassRef = authnContextClassRef;
  }
}
