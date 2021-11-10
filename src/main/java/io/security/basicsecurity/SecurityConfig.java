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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
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

//@Configuration @EnableWebSecurity에 포함됨
@EnableWebSecurity // security 관련 클래스 import해서 실행
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    // 사용자 생성..
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}1111").roles("USER"); // nope -> 패스워드 암호화 알고리즘 유형을 사용하지 않겠다

        /**
         * 해당 계정에서 user쪽 페이지도 접근하고 싶으면
         *  .roles("SYS", "USER"); 이렇게 주면 됨. 하지만 나중에 계층형으로 구현하는 법을 배울 것이므로..알아만두자
         */
        auth.inMemoryAuthentication()
            .withUser("sys").password("{noop}1111").roles("SYS");

        auth.inMemoryAuthentication()
            .withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        // 어떤 요청에도 보안 설정(인가 안되면 접근 못함)
        http.authorizeRequests()
                /* 예외 처리 부분 추가 */
            .antMatchers("/login").permitAll() // "/denied"는 인증 O, 인가 X 인 경우라 추가할 필요 없고, "/login"은 허용되야 로그인시도 가능하기 때문에 permitAll

            .antMatchers("/user").hasRole("USER")
            .antMatchers("/admin/pay").hasRole("ADMIN")
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated();

        // 인증 정책
        // form 로그인
        http.formLogin()
//            .loginPage("/loginPage") // 사용자가 설정한 로그인 페이지
            .defaultSuccessUrl("/")
            .failureUrl("/login")
            .usernameParameter("userId")
            .passwordParameter("passWd")
            .loginProcessingUrl("/login_proc")
            .successHandler(new AuthenticationSuccessHandler() {
                @Override
                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    // Authentication -> 성공 후 인증 정보가 담긴 객체
//                    System.out.println("authentication : "+authentication.getName());
//                    response.sendRedirect("/");

                    /**
                     * 예외 처리 부분 적용
                     * - 참고
                     *      : 그럼 /login 찍고 들어와서 인증 성공하면?
                     *          -> SavedRequest가 null이기 때문에 에러날 것.
                     *          -> 따라서 Null체크가 필요함
                     *          -> AuthenticationSuccessHandler의 구현체(커서두고 컨트롤 스페이스히면 확인가능)인 SavedRequestAwareAuthenticationSuccessHandler.onAuthenticationSuccess 참고
                     *              - 사실 인증 성공하면 SavedRequestAwareAuthenticationSuccessHandler 를 기본으로 사용함
                     *              - 그래서 이렇게 직접 savedRequest 처리 안해도 됨. 하지만 별도 로직을 추가하고 싶으면 상속받아 커스텀해서 이용하자
                     *                  - ex) .successHandler(new CustomAuthenticationHandler())
                     */
                    // 인증 예외 발생 전 사용자의 요청관련 정보 저장한 캐시 가져오기
                    RequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(request, response); // 사용자가 가고자 했던 정보
                    String redirectUrl = savedRequest.getRedirectUrl();
                    response.sendRedirect(redirectUrl);
                }
            })
            .failureHandler(new AuthenticationFailureHandler() {
                @Override
                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                    System.out.println("exception = " + e.getMessage());
                    response.sendRedirect("/login");
                }
            })
            /*
            *  .anyRequest().authenticated(); 로 인해 모든 요청url에 대해 인가 되어야 하는데 사용자 로그인 페이지 역시 인가가 필요하게됨.
            *   그래서 permitAll을 통해 formLogin에 작성된 url에 대해 허가 해줘야 접근할 수 있다.
            * */
            .permitAll()
        ;

        http.logout()
            .logoutUrl("/logout")
            .logoutSuccessUrl("/login")
            .addLogoutHandler(new LogoutHandler() {
                @Override
                public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                    HttpSession session = request.getSession();
                    session.invalidate(); // 세션 무효화
                }
            })
            .logoutSuccessHandler(new LogoutSuccessHandler() {
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    response.sendRedirect("/login");
                }
            })
            .deleteCookies("remember-me")
        ;
        http.rememberMe()
            .rememberMeParameter("remember")
            .tokenValiditySeconds(3600) // 세션 만료시간과 독립적으로 진행.
            .userDetailsService(userDetailsService)
        ;

        /* 동시 세션 제어 */
        http.sessionManagement()
            .maximumSessions(1)
            .maxSessionsPreventsLogin(true)
        ;

        /* 세션 고정 보호 */
//        http.sessionManagement()
//            .sessionFixation().changeSessionId()
//        ;

        /* 세션 정책 */
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        ;

        /* 인증, 인가 예외처리 */
        http.exceptionHandling()
                // 인증 예외
            .authenticationEntryPoint(new AuthenticationEntryPoint() {
                @Override
                public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                    response.sendRedirect("/login"); // 사용자가 설정한 페이지
                }
            })
                // 인가 예외
            .accessDeniedHandler(new AccessDeniedHandler() {
                @Override
                public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
                    response.sendRedirect("/denied"); // 사용자가 설정한 페이지
                }
            })
        ;
    }
}
