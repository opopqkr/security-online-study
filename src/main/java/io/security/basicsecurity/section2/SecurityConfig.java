package io.security.basicsecurity.section2;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@Order(0) // 지정해 주지 않으면 exception 발생.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(); // 인증 방식에 따라 생성되는 filter가 다름.
    }

}

@Configuration
@Order(1) // 지정해 주지 않으면 exception 발생.
class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin(); // 인증 방식에 따라 생성되는 filter가 다름.
    }

}
