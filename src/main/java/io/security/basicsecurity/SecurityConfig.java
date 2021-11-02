package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity // security 관련 클래스 import해서 실행
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        // 어떤 요청에도 보안 설정(인가 안되면 접근 못함)
        http.authorizeRequests()
            .anyRequest().authenticated();

        // 인증 정책
        // form 로그인
        http.formLogin()
//            .loginPage("/loginPage")
            .defaultSuccessUrl("/")
            .failureUrl("/login")
            .usernameParameter("userId")
            .passwordParameter("passWd")
            .loginProcessingUrl("/login_proc")
            .successHandler(new AuthenticationSuccessHandler() {
                @Override
                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    // Authentication -> 성공 후 인증 정보가 담긴 객체
                    System.out.println("authentication : "+authentication.getName());
                    response.sendRedirect("/");
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
    }
}
