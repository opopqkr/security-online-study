package io.security.basicsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

// @ComponentScan(basePackages = "io.security.basicsecurity.section1") // section1 실습
@ComponentScan(basePackages = "io.security.basicsecurity.section2") // section2 실습
@SpringBootApplication
public class BasicsecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(BasicsecurityApplication.class, args);
    }

}