package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * SpringSecurity dependency 추가 <p>
 * - 서버가 기동되면서 스프링 시큐리티의 초기화 작업 및 보안 설정 <p>
 * - 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보인 가능이 현재 시스템에 연동되어 작동 <p>
 * <p>
 * 1. 모든 요청은 인증이 되어야 자원에 접근이 가능 <p>
 * 2. 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공 <p>
 * 3. 기본 로그인 페이지 제공 <p>
 * 4. 기본 계정 한개 제공 - username : user / password 랜덤 문자열 <p>
 */
@Configuration
@EnableWebSecurity // WebSecurityConfiguration, SpringWebMvcImportSelector, OAuth2ImportSelect 를 import 하여 Web 보안 활성
// WebSecurityConfigurerAdapter - 스프링 시큐리티의 웹 보안 기능 초기화 및 설정
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * memory 방식의 사용자 생성
     *
     * @param auth - AuthenticationManagerBuilder
     * @throws Exception - exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user")
                .password("{noop}test") // prefix에 password algorithm 작성 필요.
                .roles("USER");

        auth
                .inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}test") // prefix에 password algorithm 작성 필요.
                .roles("USER", "SYS"); // 하위 권한의 자원에 접근하기 위해서는 접근하고자 하는 하위 권한 할당 필요.

        auth
                .inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}test") // prefix에 password algorithm 작성 필요.
                .roles("USER", "SYS", "ADMIN"); // 하위 권한의 자원에 접근하기 위해서는 접근하고자 하는 하위 권한 할당 필요.
    }

    /**
     * <h4>SpringSecurity Config</h4>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /* 인가(권한) API 관련 */
        urlMatchConfig(http);

        /* 인증 API 관련 */
        loginConfig(http);
        logoutConfig(http);
        rememberMeConfig(http);
        sessionConfig(http);

        /* exception handler */
        exceptionConfig(http);
    }

    /**
     * <h4>url match config</h4>
     * 인가(권한) API 관련 설정 - 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로는 뒤에 오도록 해야 함. <p>
     * <p>
     * authenticated() - 인증된 사용자의 접근을 허용 <p>
     * fullyAuthenticated() - 인증된 사용자의 접근을 허용, rememberMe 인증 제외 <p>
     * permitAll() - 모든 접근 허용 <p>
     * denyAll() - 접근 허용 하지 않음 <p>
     * anonymous() - 익명 사용자만 접근 허용, 익명 사용자와 인증된 사용자의 모든 접근을 허용하기 위해서는 permitAll() <p>
     * rememberMe() - rememberMe API를 통해 인증된 사용자의 접근을 허용 <p>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    private void urlMatchConfig(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/loginPage").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // SpEL 표현식으로 접근 허용.
                .anyRequest()
                .authenticated();
    }

    /**
     * <h4>login config</h4>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    private void loginConfig(HttpSecurity http) throws Exception {
        http
                .formLogin()
                // .loginPage("/loginPage") // 설정을 하게되면 스프링 시큐리티 로그인 페이지로 갈 수 없음.
                // .defaultSuccessUrl("/")
                // .failureUrl("/login")
                .usernameParameter("userId") // 로그인 페이지가 없을 경우 스프링 시큐리티가 제공하는 로그인 폼에서 변경됨, 추후 새로운 로그인 페이지를 만들 경우 동일하게 설정해야 함
                .passwordParameter("passWd") // 로그인
                // 페이지가 없을 경우 스프링 시큐리티가 제공하는 로그인 폼에서 변경됨, 추후 새로운 로그인 페이지를 만들 경우 동일하게 설정해야 함
                .loginProcessingUrl("/loginProcess") // 로그인 페이지가 없을 경우 스프링 시큐리티가 제공하는 로그인 폼에서 변경됨, 추후 새로운 로그인 페이지를 만들 경우 동일하게 설정해야 함
                // .failureHandler(new AuthenticationFailureHandler() {
                //     @Override
                //     public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                //         System.out.println("exception : " + e.getMessage());
                //         httpServletResponse.sendRedirect("/login");
                //     }
                // })
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
                        httpServletResponse.sendRedirect(savedRequest.getRedirectUrl());
                    }
                })
                .permitAll();
    }

    /**
     * <h4>logout config</h4>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    private void logoutConfig(HttpSecurity http) throws Exception {
        http.
                logout() // spring security logout은 post request가 default
                .logoutUrl("/logout") // logout url, default : "/logout"
                // .logoutSuccessUrl("/")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                // logoutSuccessHandler는 logoutSuccessUrl보다 더 많은 추가 작업이 가능.
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me"); // logout시 삭제하고 싶은 쿠키 명을 입력하면 삭제 됨.
    }

    /**
     * <h4>rememberMe config</h4>
     *
     * <b>RememberMeAuthenticationFilter</b><p>
     * 1. SecurityContexet안의 Authentication(인증) 객체가 Null 일 경우(사용자 Session 만료 혹은 브라우저 종료에 의한 Session이 끊길 경우) 동작. <p>
     * 2. rememberMe() API를 활성화 하여 rememberMe 쿠키를 발급 받고, 그 후 request header에 rememberMe 쿠기가 있을 경우 동작. <p>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    private void rememberMeConfig(HttpSecurity http) throws Exception {
        http
                .rememberMe() // rememberMe 기능 작동
                .rememberMeParameter("remember-me") // rememberMe Parameter Setting, default : remember-me
                .tokenValiditySeconds(3600) // token 유효 기간, default : 14일
                // .alwaysRemember(true) // rememberMe 기능이 활성화 되지 않아도 항상 실행
                .userDetailsService(userDetailsService); // rememberMe 인증 시 user 계정을 조회하는 처리를 위한 클래스
    }

    /**
     * <h4>session config</h4>
     * <b>SessionManagementFilter</b><p>
     * - 정책, 관리, 제어, 보호등의 기능을 함 <p>
     * <p>
     * <p>
     * 세션 고정 보호 - 세션 고정 공격(로그인 시 발급 받은 세션 ID를 공격자가 세션 하이제킹 하여 공격) 방지. <p>
     * 인증 할 때마다 세션을 새로 생성하며, 설정하지 않아도 SpringSecurity에서 default로 설정함. <p>
     * <p>
     * <p>
     * 동시 세션 제어 - 동일한 계정의 최대 세션 허용 개수 초과 시 처리 <p>
     *
     * <b>ConcurrentSessionFilter</b>와 연계 하여 사용. <p>
     * - 매 요청 마다 현재 사용자의 세션 만료 여부 체크. <p>
     * - 세션이 만료 되었을 경우 즉시 만료 처리. <p>
     * <p>
     * 1. 이전 세션 정보 만료 처리 <p>
     * 2. 인증 실패 처리 (로그인 차단) <p>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    private void sessionConfig(HttpSecurity http) throws Exception {
        http
                /* 세션 정책 */
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // default, 스프링 시큐리티가 필요 시 생성.
                // .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 스프링 시큐리티가 항상 세션 생성.
                // .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용.
                // .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음, 세션을 사용하지 않은 인증 방식에 사용(JWT 등)
                /* 세션 고정 보호 */
                .sessionFixation()
                .changeSessionId() // default, Servlet 3.1 이상
                // .none() // 사용 하지 않음, 세션고정공격에 취약.
                // .newSession() // 이전의 세션에서 설정한 속성 값들을 사용 할 수 없음.
                // .migrateSession() //  Servlet 3.1 미만.
                /* 동시 세션 제어 */
                .maximumSessions(1) // 최대 세션 허용 갯수, -1은 무제한
                .maxSessionsPreventsLogin(true); // true - 로그인 차단, false(default) - 이전 세션 정보 만료
    }

    /**
     * <h4>ExceptionHandling config</h4>
     * <b>ExceptionTranslationFilter (인증 및 인가 관련 예외 처리)</b> <p>
     * - FilterSecurityInterceptorFilter에서 예외가 발생하여 ExceptionTranslationFilter에 throw(SpringSecurity filter 마지막에 위치) <p>
     * <p>
     * <p>
     * <b>AuthenticationException (인증 예외 처리)</b> <p>
     * - AuthenticationEntryPoint call -> 로그인 페이지 이동 or 401 <p>
     * <p>
     * - RequestCache 사용자의 이전 요청정보를 세션에 저장하고 이를 꺼내오는 캐시 메커니즘
     * (login success Handler의 AuthenticationSuccessHandler()로 control)<p>
     * - SavedRequest.class -> RequestCache 구현체에서 request 정보를 가져와 사용자가 요청했던 request 파라미터 및 header value 저장 <p>
     * <p>
     * <b>AccessDeniedException (인가 예외 처리)</b> <p>
     * - AccessDeniedHandler에서 예외처리하도록 제공 <p>
     *
     * @param http - HttpSecurity.class : 보안 기능을 설정할 수 있는 API(인증 및 인가 API)를 제공
     * @throws Exception - exception
     */
    private void exceptionConfig(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                // .authenticationEntryPoint(new AuthenticationEntryPoint() {
                //     @Override
                //     public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                //          System.out.println("AuthenticationEntryPoint commence.");
                //          httpServletResponse.sendRedirect("/loginPage"); // spring security 로그인 페이지가 아닌 직접 구현한 페이지로 이동.
                //      }
                //  })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/denied");
                    }
                });
    }
}