package ddf.security.assertion.impl;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ddf.security.assertion.SecurityAssertion;
import java.security.Principal;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.AuthzDecisionStatement;

public class SecurityAssertionJwt implements SecurityAssertion {

  private final JWT token;

  private final List<String> usernameAttributeList;

  private JWTClaimsSet jwtClaimsSet;

  public SecurityAssertionJwt(JWT token, List<String> usernameAttributeList) {
    this.token = token;
    this.usernameAttributeList = usernameAttributeList;
    try {
      jwtClaimsSet = token.getJWTClaimsSet();
    } catch (ParseException e) {
      // do something
    }
  }

  @Override
  public Principal getPrincipal() {
    return () -> {
      try {
        return jwtClaimsSet.getStringClaim("email");
      } catch (ParseException e) {
        return "unknown";
      }
    };
  }

  @Override
  public String getIssuer() {
    return jwtClaimsSet.getIssuer();
  }

  @Override
  public List<AttributeStatement> getAttributeStatements() {
    return new ArrayList<>();
  }

  @Override
  public List<AuthnStatement> getAuthnStatements() {
    return new ArrayList<>();
  }

  @Override
  public List<AuthzDecisionStatement> getAuthzDecisionStatements() {
    return new ArrayList<>();
  }

  @Override
  public List<String> getSubjectConfirmations() {
    return new ArrayList<>();
  }

  @Override
  public Set<Principal> getPrincipals() {
    return new HashSet<>();
  }

  @Override
  public String getTokenType() {
    return "jwt";
  }

  @Override
  public SecurityToken getSecurityToken() {
    return null;
  }

  @Override
  public Date getNotBefore() {
    return jwtClaimsSet.getNotBeforeTime();
  }

  @Override
  public Date getNotOnOrAfter() {
    return jwtClaimsSet.getExpirationTime();
  }

  @Override
  public boolean isPresentlyValid() {
    return true;
  }
}
