/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package ddf.security.assertion.jwt.impl;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ddf.security.assertion.Attribute;
import ddf.security.assertion.AttributeStatement;
import ddf.security.assertion.AuthenticationStatement;
import ddf.security.assertion.SecurityAssertion;
import java.security.Principal;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;

public class SecurityAssertionJwt implements SecurityAssertion {

  private final JWT token;

  private final List<String> usernameAttributeList;

  private JWTClaimsSet jwtClaimsSet;

  private List<AttributeStatement> attributeStatements;

  private List<AuthenticationStatement> authenticationStatements = new ArrayList<>();

  public SecurityAssertionJwt(JWT token, List<String> usernameAttributeList) {
    this.token = token;
    this.usernameAttributeList = usernameAttributeList;
    try {
      jwtClaimsSet = token.getJWTClaimsSet();
      Map<String, Object> claims = jwtClaimsSet.getClaims();
      attributeStatements = new ArrayList<>();
      AttributeStatement attributeStatement = new AttributeStatementJwt();
      attributeStatements.add(attributeStatement);
      for (Map.Entry<String, Object> entry : claims.entrySet()) {
        Attribute attribute = new AttributeJwt();
        attribute.setName(entry.getKey());
        List<String> values = new ArrayList<>();
        if (entry.getValue() instanceof Collection) {
          Collection collection = (Collection) entry.getValue();
          for (Object next : collection) {
            values.add(String.valueOf(next));
          }
        } else {
          values.add(String.valueOf(entry.getKey()));
        }
        attribute.setValues(values);
        attributeStatement.addAttribute(attribute);
      }
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
    return Collections.unmodifiableList(attributeStatements);
  }

  @Override
  public List<AuthenticationStatement> getAuthnStatements() {
    return Collections.unmodifiableList(authenticationStatements);
  }

  @Override
  public List<String> getSubjectConfirmations() {
    return new ArrayList<>();
  }

  @Override
  public Set<Principal> getPrincipals() {
    Set<Principal> principals = new HashSet<>();
    Principal primary = getPrincipal();
    principals.add(primary);
    principals.add(new RolePrincipal(primary.getName()));
    for (AttributeStatement attributeStatement : getAttributeStatements()) {
      for (Attribute attr : attributeStatement.getAttributes()) {
        if (StringUtils.containsIgnoreCase(attr.getName(), "role")) {
          for (final String obj : attr.getValues()) {
            principals.add(new RolePrincipal(obj));
          }
        }
      }
    }

    return principals;
  }

  @Override
  public String getTokenType() {
    return "jwt";
  }

  @Override
  public Object getToken() {
    return token;
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
