package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "Anyone with user permissions or higher can access it.";
    }

    @GetMapping("/admin/**")
    public String adminAll() {
        return "Access only to users with sys and admin privileges.";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "Access only by users with admin privileges.";
    }
}