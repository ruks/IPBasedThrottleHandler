package org.wso2.carbon.sample.throttling;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.neethi.PolicyEngine;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.SynapseException;
import org.apache.synapse.commons.throttle.core.*;
import org.apache.synapse.config.Entry;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.gateway.handlers.throttling.APIThrottleConstants;
import org.wso2.carbon.apimgt.gateway.handlers.throttling.ApplicationThrottleController;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.governance.registry.extensions.utils.APIUtils;

import java.util.Map;
import java.util.TreeMap;

public class IPBasedThrottling extends AbstractHandler {

    private static final Log log = LogFactory.getLog(IPBasedThrottling.class);

    private static final String RESOURCE_PATH = "/apimgt/applicationdata/tiers.xml";
    private static final String THROTTLE_POLICY_KEY = "gov:" + RESOURCE_PATH;

    /**
     * The Throttle object - holds all runtime and configuration data
     */
    private volatile Throttle throttle;

    private RoleBasedAccessRateController applicationRoleBasedAccessController;

    /**
     * The key for getting the throttling policy - key refers to a/an [registry] entry
     */
    private String policyKey = null;
    /**
     * The concurrent access control group id
     */
    private String id;
    /**
     * Version number of the throttle policy
     */
    private long version;

    public IPBasedThrottling() {
        this.applicationRoleBasedAccessController = new RoleBasedAccessRateController();
    }

    @Override
    public boolean handleRequest(MessageContext messageContext) {

        return doThrottle(messageContext);
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {

        return doThrottle(messageContext);
    }

    private boolean doThrottle(MessageContext messageContext) {
        boolean canAccess = true;
        boolean isResponse = messageContext.isResponse();
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        ConfigurationContext cc = axis2MC.getConfigurationContext();
        synchronized (this) {

            if (!isResponse) {
                initThrottle(messageContext, cc);
            }
        }
        // if the access is success through concurrency throttle and if this is a request message
        // then do access rate based throttling
        if (!isResponse && throttle != null) {
            AuthenticationContext authContext = APISecurityUtils.getAuthenticationContext(messageContext);
            String tier;
            if (authContext != null) {
                AccessInformation info = null;
                try {

                    String ipBasedKey = (String) ((TreeMap) axis2MC.
                            getProperty("TRANSPORT_HEADERS")).get("X-Forwarded-For");
                    if (ipBasedKey == null) {
                        ipBasedKey = (String) axis2MC.getProperty("REMOTE_ADDR");
                    }
                    tier = authContext.getApplicationTier();
                    //ThrottleContext apiThrottleContext = ApplicationThrottleController.getApplicationThrottleContext(messageContext,cc,tier);

                    ThrottleContext apiThrottleContext =
                            ApplicationThrottleController.
                                    getApplicationThrottleContext(messageContext, null,
                                            authContext.getApplicationId(),
                                            THROTTLE_POLICY_KEY);
//                    ThrottleContext apiThrottleContext2 =
//                            ApplicationThrottleController.
//                                    getApplicationThrottleContext(messageContext, cc, tier,authContext.getApplicationId());
                    //    if (isClusteringEnable) {
                    //      applicationThrottleContext.setConfigurationContext(cc);
                    apiThrottleContext.setThrottleId(id);
                    info = applicationRoleBasedAccessController.canAccess(apiThrottleContext,
                            ipBasedKey, tier);
                    canAccess = info.isAccessAllowed();
                } catch (ThrottleException e) {
                    handleException("Error while trying evaluate IPBased throttling policy", e);
                }
            }
        }
        if (!canAccess) {
            handleThrottleOut(messageContext);
            return false;
        }

        return canAccess;
    }


    private void initThrottle(MessageContext synCtx, ConfigurationContext cc) {
        if (policyKey == null) {
            log.info("+++++ Throttle policy unspecified for the API ++++++++");
            throw new SynapseException("Throttle policy unspecified for the API");
        }
        Entry entry = synCtx.getConfiguration().getEntryDefinition(policyKey);
        if (entry == null) {
            log.info("++++ Cannot find throttling policy using key+++"+ policyKey);
            handleException("Cannot find throttling policy using key: " + policyKey);
            return;
        }
        Object entryValue = null;
        boolean reCreate = false;
        if (entry.isDynamic()) {
            if ((!entry.isCached()) || (entry.isExpired()) || throttle == null) {
                log.info("++++++++++++Is dynamic ++++");
                entryValue = synCtx.getEntry(this.policyKey);
                if (this.version != entry.getVersion()) {
                    log.info("++++++++++++Is dynamic and isCached+++++");
                    reCreate = true;
                }
            }
        } else if (this.throttle == null) {
            entryValue = synCtx.getEntry(this.policyKey);
        }
        if (reCreate || throttle == null) {
            if (entryValue == null || !(entryValue instanceof OMElement)) {
                log.info("Unable to load throttling policy using key: " + policyKey);
                handleException("Unable to load throttling policy using key: " + policyKey);
                return;
            }
            version = entry.getVersion();
            try {
                // Creates the throttle from the policy
                throttle = ThrottleFactory.createMediatorThrottle(
                        PolicyEngine.getPolicy((OMElement) entryValue));

            } catch (ThrottleException e) {
                log.info("++++Error processing the throttling policy++",e);
                handleException("Error processing the throttling policy", e);
            }
        }
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setPolicyKey(String policyKey) {
        this.policyKey = policyKey;
    }

    public String gePolicyKey() {
        return policyKey;
    }

    private void handleException(String msg, Exception e) {
        log.error(msg, e);
        throw new SynapseException(msg, e);
    }

    private void handleException(String msg) {
        log.error(msg);
        throw new SynapseException(msg);
    }

    private OMElement getFaultPayload() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace ns = fac.createOMNamespace(APIThrottleConstants.API_THROTTLE_NS,
                APIThrottleConstants.API_THROTTLE_NS_PREFIX);
        OMElement payload = fac.createOMElement("fault", ns);
        OMElement errorCode = fac.createOMElement("code", ns);
        errorCode.setText(String.valueOf(APIThrottleConstants.API_THROTTLE_OUT_ERROR_CODE));
        OMElement errorMessage = fac.createOMElement("message", ns);
        errorMessage.setText("Message Throttled Out");
        OMElement errorDetail = fac.createOMElement("description", ns);
        errorDetail.setText("You have exceeded your quota");

        payload.addChild(errorCode);
        payload.addChild(errorMessage);
        payload.addChild(errorDetail);
        return payload;
    }

    private void handleThrottleOut(MessageContext messageContext) {
        messageContext.setProperty(SynapseConstants.ERROR_CODE, 900800);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, "@@@@@@@@@@@@@@Message throttled out#############");

        Mediator sequence = messageContext.getSequence(APIThrottleConstants.API_THROTTLE_OUT_HANDLER);
        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }         // By default we send a 503 response back
        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            Utils.setFaultPayload(messageContext, getFaultPayload());
        } else {
            log.info("Throttled out++++++++++++++");
            Utils.setSOAPFault(messageContext, "Server", "##############Message Throttled Out@@@@@@@@@@@@@@@@",
                    "You have exceeded your quota");
        }
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        if (APIUtil.isCORSEnabled()) {
            /* For CORS support adding required headers to the fault response */
            Map headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
            headers.put(APIConstants.CORSHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, APIUtil.getAllowedOrigins());
            headers.put(APIConstants.CORSHeaders.ACCESS_CONTROL_ALLOW_METHODS, APIUtil.getAllowedMethods());
            headers.put(APIConstants.CORSHeaders.ACCESS_CONTROL_ALLOW_HEADERS, APIUtil.getAllowedHeaders());
            axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
        }

        Utils.sendFault(messageContext, HttpStatus.SC_SERVICE_UNAVAILABLE);
    }

}
