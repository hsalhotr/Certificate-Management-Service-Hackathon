package com.hackweek.certificatemanagementservice;

import com.hackweek.certificatemanagementservice.awsHSM.LoginHSM;
import com.hackweek.certificatemanagementservice.signing.SignOperation;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CertificateManagementServiceController {

    @RequestMapping("/sign")
    public String sign() throws Exception {

        // login to hsm
        LoginHSM.login();

        //Sign
        SignOperation.performSignOps();


        return "Get you signed document";
    }
}
