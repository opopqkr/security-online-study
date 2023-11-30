package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * 스프링 시큐리티 의존성 추가
 * - 서버가 기동되면서 스프링 시큐리티의 초기화 작업 및 보안 설정
 * - 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보인 가능이 현재 시스템에 연동되어 작동
 * <p>
 * 1. 모든 요청은 인증이 되어야 자원에 접근이 가능
 * 2. 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공
 * 3. 기본 로그인 페이지 제공
 * 4. 기본 계정 한개 제공 - username : user / password 랜덤 문자열
 */
@Configuration
@EnableWebSecurity
/* @EnableWebSecurity
   - WebSecurityConfiguration, SpringWebMvcImportSelector, OAuth2ImportSelect 를 import 하여 Web 보안 활성
 */
public class SecurityConfig extends WebSecurityConfigurerAdapter { // WebSecurityConfigurerAdapter - 스프링 시큐리티의 웹 보안 기능 초기화 및 설정

    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * &#064;Param - HttpSecurity : 세부적인 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated(); // 인가

        http
                .formLogin()
//                .loginPage("/loginPage") // 인증을 받지 않아도 접근 허용해야 함
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId") // 로그인 페이지가 없을 경우 스프링 시큐리티가 제공하는 로그인 폼에서 변경됨, 추후 새로운 로그인 페이지를 만들 경우 동일하게 설정해야 함
                .passwordParameter("passWd") // 로그인
                // 페이지가 없을 경우 스프링 시큐리티가 제공하는 로그인 폼에서 변경됨, 추후 새로운 로그인 페이지를 만들 경우 동일하게 설정해야 함
                .loginProcessingUrl("/loginProcess") // 로그인 페이지가 없을 경우 스프링 시큐리티가 제공하는 로그인 폼에서 변경됨, 추후 새로운 로그인 페이지를 만들 경우 동일하게 설정해야 함
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("exception : " + e.getMessage());
                        httpServletResponse.sendRedirect("/login");

                    }
                })
                .permitAll(); // 인증

        http.
                logout() // spring security logout은 post request가 default
                .logoutUrl("/logout") // logout url - default = "/logout"
                .logoutSuccessUrl("/")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { // logoutSuccessHandler는 logoutSuccessUrl보다 더 많은 추가 작업이 가능.
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                });
        // .deleteCookies("remember-me") // logout시 삭제하고 싶은 쿠키 명을 입력하면 삭제 됨.

        /*
                RememberMeAuthenticationFilter
                -> SecurityContexet안의 Authentication(인증) 객체가 Null 일 경우 동작
                   (사용자 Session 만료 혹은 브라우저 종료에 의한 Session이 끊길 경우)
                -> rememberMe() API를 활성화 하여 rememberMe 쿠키를 발급 받고,
                   그 후 request header에 rememberMe 쿠기가 있을 경우
        */
        http
                .rememberMe() // rememberMe 기능 작동
                .rememberMeParameter("remember") // rememberMe Parameter Setting, default : remember-me
                .tokenValiditySeconds(3600) // token 유효 기간, default : 14일
//                .alwaysRemember(true) // rememberMe 기능이 활성화 되지 않아도 항상 실행
                .userDetailsService(userDetailsService); // rememberMe 인증 시 user 계정을 조회하는 처리를 위한 클래스
    }
}
