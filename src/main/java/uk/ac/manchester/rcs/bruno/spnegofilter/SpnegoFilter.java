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

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

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

/**
 * This is a small test filter to test SPNEGO authentication.
 * 
 * @author Bruno Harbulot
 */
public class SpnegoFilter extends Filter {
	private String jaasName;
	
	private GSSManager gssManager;
	private GSSCredential gssServerCreds;
	
	public SpnegoFilter(String jaasName) {
		Engine.getInstance().getRegisteredAuthentications().add(0, new SpnegoAuthenticationHelper());
		this.jaasName = jaasName;
	}
	
	private GSSContext gssInit() throws Exception {
		LoginContext context = new LoginContext(jaasName, new TextCallbackHandler());
	    context.login();
	    Subject subject = context.getSubject();
		GssInitAction gssInitAction = new GssInitAction();
		Subject.doAs(subject, gssInitAction);
		context.logout();
		return gssInitAction.gssContext;
	}
	
	private byte[] gssAcceptSecContext(GSSContext gssContext, byte[] token) throws Exception {
		LoginContext context = new LoginContext(jaasName, new TextCallbackHandler());
	    context.login();
	    Subject subject = context.getSubject();
	    GssAcceptSecContextAction action = new GssAcceptSecContextAction(gssContext, token);
		token = Subject.doAs(subject, action);
		context.logout();
		return token;
	}

	@Override
	protected int doHandle(Request request, Response response) {
		
		int result = Filter.STOP;
		@SuppressWarnings("unchecked")
		Series<Parameter> reqHeaders = (Series<Parameter>)request.getAttributes().get("org.restlet.http.headers");
		
		String authorizationHeader = reqHeaders.getFirstValue("Authorization");
		

		try {
			GSSContext gssContext = gssInit();
			
			System.out.println("*** Received this authorization header: "+authorizationHeader);

			Principal authenticatedPrincipal = null;
			
			Form spnegoParams = new Form();
			
			if (authorizationHeader != null) {
				if (authorizationHeader.startsWith("Negotiate ")) {
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
				result = Filter.CONTINUE;
				super.doHandle(request, response);
			} else {
				response.setStatus(Status.CLIENT_ERROR_UNAUTHORIZED);
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return result;
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
}
