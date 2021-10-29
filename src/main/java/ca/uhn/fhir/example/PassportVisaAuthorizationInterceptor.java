package ca.uhn.fhir.example;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.Observation;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.net.URL;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.security.spec.*;
import java.util.*;

public class PassportVisaAuthorizationInterceptor extends AuthorizationInterceptor {
    private static final Logger logger
            = LoggerFactory.getLogger(PassportVisaAuthorizationInterceptor.class);

    private static final String PASSPORT_ISSUER = "https://broker.nagim.dev";
    private static final String PASSPORT_JWKS = "https://broker.nagim.dev/.well-known/jwks";

    private static final String VISA_TRUSTED_ISSUER = "https://didact-patto.dev.umccr.org";
    private static final String VISA_TRUSTED_JWKS = "https://didact-patto.dev.umccr.org/.well-known/jwks";

    @Override
    public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

        // Start with a builder that allows all activity we want to allow the public to do
        RuleBuilder builder = new RuleBuilder();

        builder.allow().metadata();

        // Process this header
        String authHeader = theRequestDetails.getHeader("Authorization");

        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7, authHeader.length());

                // step 1 is to verify the passport and if valid return the claims
                // the passport processor is configured to do all this for us
                JWTClaimsSet claimsSet = getPassportProcessor(PASSPORT_ISSUER, PASSPORT_JWKS).process(token, null);

                // our claims now need to be decomposed into a set of visas from different issuers
                Map<String, Object> ga4ghMap = (Map<String, Object>) claimsSet.getClaim("ga4gh");
                Map<String, Map<String, String>> visasMap = (Map<String, Map<String, String>>) ga4ghMap.get("iss");

                // in our case - we are interested in a single issuer - the DAC
                // (if needed we could also iterate through looking for assertions from a variety of sources)
                Map<String, String> authVisaMap = visasMap.get(VISA_TRUSTED_ISSUER);

                // the plain text signature we treat as a bytes sequence encoded by UTF-8 (we get this guarantee from the JSON structure it arrived in)
                String vString = authVisaMap.get("v");
                byte[] vBytes = vString.getBytes(StandardCharsets.UTF_8);

                // the signature we know is a base64 url encoded byte array
                byte[] signatureBytes = Base64.getUrlDecoder().decode(authVisaMap.get("s"));

                // make a verifier object that fetches the corresponding keys and is all initialised
                Ed25519Signer visaVerifier = getVisaVerifier(VISA_TRUSTED_ISSUER, VISA_TRUSTED_JWKS, authVisaMap.get("k"));

                // update the verifier with the visa content
                visaVerifier.update(vBytes, 0, vBytes.length);

                // and then verify the signature
                if (visaVerifier.verifySignature(signatureBytes)) {

                    for (String x : vString.split(" ")) {
                        if (x.startsWith("c:")) {
                            String manifestId = x.substring(2);

                            try(java.io.InputStream is = new java.net.URL(String.format("%s/api/manifest/%s", VISA_TRUSTED_ISSUER, manifestId)).openStream()) {
                                String contents = new String(is.readAllBytes());

                                JSONObject jo = new JSONObject(contents);

                                logger.info(jo.toString(2));
                            }

                            // builder.allow()
                            builder.allow().read().allResources().withAnyId().andThen()
                                    .allow().write().resourcesOfType(Observation.class).inCompartment("Patient", new IdType("Patient/123"));
                        }
                    }

                }
            }
        } catch (Exception e) {
            logger.error(e.toString());
        }

        return builder.build();
    }

    private Ed25519Signer getVisaVerifier(String iss, String jwksUrl, String kid) throws Exception {
        JWKSource<SecurityContext> keySource =
                new RemoteJWKSet<>(new URL(jwksUrl), new DefaultResourceRetriever(5000, 5000));

        JWKSelector keySelector = new JWKSelector(new JWKMatcher.Builder().algorithm(JWSAlgorithm.EdDSA).keyID(kid).build());

        List<JWK> visaKeys = keySource.get(keySelector, null);

        if (visaKeys.size() != 1)
            throw new Exception("Did not find corresponding key for kid");

        // the Java crypto libraries (as of October 2021) don't have complete Edwards Curve support.. so whilst
        // I think they can generate/verify signatures - the support around constructing public key objects is
        // weak (it needs the actual curve parameters isOdd, y themselves sent to the public key constructor.. we ain't got time
        // for that nonsense).
        // https://stackoverflow.com/questions/65780235/ed25519-in-jdk-15-parse-public-key-from-byte-array-and-verify
        //
        // So instead using Bouncy Castle - which does have a public key constructor that takes
        // a public key represented as 32 bytes - and is already kind of used by JOSE anyhow

        OctetKeyPair visaKeyPair = visaKeys.get(0).toOctetKeyPair();
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(visaKeyPair.getDecodedX(), 0);
        Ed25519Signer visaVerifier = new Ed25519Signer();
        visaVerifier.init(false, publicKey);

        return visaVerifier;
    }

    private ConfigurableJWTProcessor<SecurityContext> getPassportProcessor(String iss, String jwksUrl) throws java.net.MalformedURLException {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                new DefaultJWTProcessor<>();

        JWKSource<SecurityContext> keySource =
                new RemoteJWKSet<>(new URL(jwksUrl), new DefaultResourceRetriever(5000, 5000));

        // whilst we are currently only using RS256, there is no reason we should not allow others
        Set<JWSAlgorithm> expectedAlgSet = new HashSet<>();
        expectedAlgSet.add(JWSAlgorithm.RS256);
        expectedAlgSet.add(JWSAlgorithm.RS384);
        expectedAlgSet.add(JWSAlgorithm.RS512);

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(expectedAlgSet, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens issued by the Connect2id
        // server, may differ with other servers
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder()
                        .issuer(iss)
                        .build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp", "jti"))));

        return jwtProcessor;
    }



}
