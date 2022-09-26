package com.hackweek.certificatemanagementservice;

import com.hackweek.certificatemanagementservice.awsHSM.LoginHSM;
import com.hackweek.certificatemanagementservice.signing.SignOperation;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.Security;

@RestController
public class CertificateManagementServiceController {

    @RequestMapping("/sign")
    public String sign() throws Exception {

        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            throw ex;
        }
        // login to hsm
        LoginHSM.login();

        //Sign
        SignOperation.performSignOps();


        return "Get you signed document";
    }
}
