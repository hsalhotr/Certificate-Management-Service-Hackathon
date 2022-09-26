package com.hackweek.certificatemanagementservice.awsHSM;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.LoginManager;

import java.awt.*;
import java.io.IOException;
import java.security.Key;
import java.security.Security;

public class LoginHSM {

    public static void login() throws Exception {

        String user = "example_user", pass="NewPassword", partition="PARTITION_1";

        loginWithExplicitCredentials(user, pass, partition);


       // logout();
    }
    public static void loginWithExplicitCredentials(String user, String pass, String partition) {
        LoginManager lm = LoginManager.getInstance();
        try {
            lm.login(partition, user, pass);
            System.out.printf("\nLogin successful!\n\n");
        } catch (CFM2Exception e) {
            if (CFM2Exception.isAuthenticationFailure(e)) {
                System.out.printf("\nDetected invalid credentials\n\n");
            }

            e.printStackTrace();
        }
    }

    public static void logout() {
        try {
            LoginManager.getInstance().logout();
        } catch (CFM2Exception e) {
            e.printStackTrace();
        }
    }

}
