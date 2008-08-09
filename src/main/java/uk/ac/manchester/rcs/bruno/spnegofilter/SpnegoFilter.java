/*

Copyright (c) 2008, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
    * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

 */
package uk.ac.manchester.rcs.bruno.spnegofilter;

import java.math.BigInteger;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.restlet.Filter;
import org.restlet.data.ChallengeRequest;
import org.restlet.data.ChallengeResponse;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.Form;
import org.restlet.data.Parameter;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.data.Status;
import org.restlet.util.Series;

import com.noelios.restlet.Engine;
import com.noelios.restlet.authentication.AuthenticationHelper;
import com.noelios.restlet.util.Base64;
import com.sun.security.auth.callback.TextCallbackHandler;
import com.sun.security.auth.module.Krb5LoginModule;

/**
 * This is a small test filter to test SPNEGO authentication.
 * Treat as experimental!
 * 
 * @author Bruno Harbulot
 */
public class SpnegoFilter extends Filter {	
	private GSSManager gssManager;
	private GSSCredential gssServerCreds;
	
	public SpnegoFilter() {
		Engine.getInstance().getRegisteredAuthentications().add(0, new SpnegoAuthenticationHelper());
	}
	
	private Krb5LoginModule krb5Login(Subject subject) throws LoginException {
		Map<String, String> state = new HashMap<String, String>();

		@SuppressWarnings("unchecked")
		Map<String, String> options = (Map<String, String>)getContext().getAttributes().get("krb5options");
		
		Krb5LoginModule login = new Krb5LoginModule();
		login.initialize(subject, new TextCallbackHandler(), state, options);
		if(login.login()) {
			login.commit();
		}
		return login;
	}
	
	private GSSContext gssInit() throws Exception {
		Subject subject = new Subject();
		Krb5LoginModule login = krb5Login(subject);
		
		GssInitAction gssInitAction = new GssInitAction();
		Subject.doAs(subject, gssInitAction);
		login.logout();
		return gssInitAction.gssContext;
	}

	
	private byte[] gssAcceptSecContext(GSSContext gssContext, byte[] token) throws Exception {
		Subject subject = new Subject();
		Krb5LoginModule login = krb5Login(subject);
		
	    GssAcceptSecContextAction action = new GssAcceptSecContextAction(gssContext, token);
		token = Subject.doAs(subject, action);
		login.logout();
		return token;
	}
	
	private class GssInitAction implements PrivilegedExceptionAction<Object> {
		public GSSContext gssContext;
		@Override
		public Object run() throws Exception {
			gssManager = GSSManager.getInstance();
			Oid spnegoOid = new Oid("1.3.6.1.5.5.2");
			gssServerCreds = gssManager.createCredential(null,
					GSSCredential.DEFAULT_LIFETIME, spnegoOid,
					GSSCredential.ACCEPT_ONLY);
			gssContext = gssManager.createContext(
				    (GSSCredential)gssServerCreds);
			return null;
		}
	}
	
	private class GssAcceptSecContextAction implements PrivilegedExceptionAction<byte[]> {
		private final byte[] token;
		private final GSSContext gssContext;
		public GssAcceptSecContextAction(GSSContext gssContext, byte[] token) {
			this.token = token;
			this.gssContext = gssContext;
		}
		@Override
		public byte[] run() throws Exception {
			byte[] token = gssContext.acceptSecContext(this.token, 0, this.token.length);
			return token;
		}
	}

    public static final ChallengeScheme HTTP_SPNEGO = new ChallengeScheme(
            "HTTP_SPNEGO", "Negotiate");
	
	public static class SpnegoAuthenticationHelper extends AuthenticationHelper {
		public static final String SPNEGO_TOKEN_PARAM_NAME = "spnego-token";
		
		public SpnegoAuthenticationHelper() {
			super(HTTP_SPNEGO, false, true);
		}
		
		@Override
		public void formatCredentials(StringBuilder arg0,
				ChallengeResponse arg1, Request arg2, Series<Parameter> arg3) {
			// TODO Auto-generated method stub
			
		}
		
	    public void formatParameters(StringBuilder sb,
	            Series<Parameter> parameters, ChallengeRequest request) {
	    	String challengeString = parameters.getFirstValue(SPNEGO_TOKEN_PARAM_NAME);
	    	if (challengeString != null) {
	    		sb.append(challengeString);
	    	}
	    }
	}
	
	

	@Override
	protected int doHandle(Request request, Response response) {
		
		int result = Filter.STOP;
		@SuppressWarnings("unchecked")
		Series<Parameter> reqHeaders = (Series<Parameter>)request.getAttributes().get("org.restlet.http.headers");
		
		String authorizationHeader = reqHeaders.getFirstValue("Authorization");
		

		try {
			// Initialises the GSSContext
			GSSContext gssContext = gssInit();
			
			System.out.println("*** Received this authorization header: "+authorizationHeader);

			Principal authenticatedPrincipal = null;
			
			Form spnegoParams = new Form();
			
			// Reads the autorisation header
			if (authorizationHeader != null) {
				if (authorizationHeader.startsWith("Negotiate ")) {
					/* 
					 * If the request contains a Negotiate auth header, the token is passed to the GSS context.
					 * The token obtained in return (from the GSS API) will be sent back in the response.
					 */
					String spnegoOutputTokenString = "";
					
					String spnegoInputTokenString = authorizationHeader.substring("Negotiate ".length());
					byte[] spnegoToken;
					try {
						BigInteger integerToken = new BigInteger(spnegoInputTokenString, 16);
						spnegoToken = integerToken.toByteArray();
					} catch (NumberFormatException e) {
						spnegoToken = Base64.decode(spnegoInputTokenString);
					}
					
					if (spnegoToken.length != 0) {
						spnegoToken = gssAcceptSecContext(gssContext, spnegoToken);
						spnegoOutputTokenString = Base64.encode(spnegoToken, false);
					}
					
					spnegoParams.add(SpnegoAuthenticationHelper.SPNEGO_TOKEN_PARAM_NAME, spnegoOutputTokenString);
					System.out.println("*** Sending this Negotiate challenge: "+spnegoOutputTokenString);
				} else if (authorizationHeader.startsWith("Basic ")) {
					/* 
					 * If the request contains a Basic auth header, it is used for authentication.
					 * For the purpose of this test, username and password are both "basic".
					 */
					String basicAuthEncodedCredentials = authorizationHeader.substring("Basic ".length());
					String basicAuthDecodedCredentials = new String(Base64.decode(basicAuthEncodedCredentials));
					if ("basic:basic".equalsIgnoreCase(basicAuthDecodedCredentials)) {
						authenticatedPrincipal = new Principal() {
							public String getName() {
								return "basic";
							}
						};
					}
				} else {
					response.setStatus(Status.CLIENT_ERROR_UNAUTHORIZED);
				}
			}
		
			/*
			 * Adds two challenges.
			 */
			ChallengeRequest challengeReq = new ChallengeRequest(HTTP_SPNEGO, null);
			challengeReq.setParameters(spnegoParams);
			response.getChallengeRequests().add(challengeReq);
			
			ChallengeRequest basicChallengeReq = new ChallengeRequest(ChallengeScheme.HTTP_BASIC, "Test Realm");
			response.getChallengeRequests().add(basicChallengeReq);
			
			
			if (gssContext.isEstablished()) {
				try {
					final GSSName srcName = gssContext.getSrcName();
					System.out.println("*** Authenticated via GSS/SPNEGO: "+srcName);
					System.out.println("    Type: "+srcName.getStringNameType());
					
					authenticatedPrincipal = new Principal() {
						public String getName() {
							return srcName.toString();
						}
					};
				} catch (GSSException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} 
			
			if (authenticatedPrincipal != null) {
				// The following is only used as a quick way to pass something to show on the test web-page.
				request.getAttributes().put("ThePrincipal", authenticatedPrincipal);
				result = super.doHandle(request, response);
			} else {
				response.setStatus(Status.CLIENT_ERROR_UNAUTHORIZED);
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return result;
	}
}
