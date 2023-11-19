package com.sp.fc.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 로그인 정보가 넘어오지 않을때는 filter에 breakPoint를 걸어서 값을 확인해보자
    UsernamePasswordAuthenticationFilter filter;
    CsrfFilter csrfFilter;

    // 관리자가 유저페이지데 접근 할 수 있게 하기
    @Bean
    RoleHierarchy roleHierarchy() {
      RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
      roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
      return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            // 루트 페이지(메인 페이지)를 제외하고는 모두 막아보기

                            // 루트 페이지(메인 페이지)는 모두 들어오게 하고
                            .antMatchers("/").permitAll()
                            // anyRequest에 대해서는 authenticate에게 허락을 받고 들어와라
                            // anyRequest는 무슨 의미지??/
                            .anyRequest().authenticated()
                            ;
                })

                // "/" 외 url을 접근할때는 제너레이션default페이지가 뜨는데,
                // 우리가 만들어놓은 로그인 페이지로 custom 하겠다.
                .formLogin(
                    login -> login.loginPage("/login")
                    // permitAll을 하지 않으면, 위에 설정한 것에 의하면 메인 페이지 말고는
                    // 다 authenticate에게 허락을 받고 들어가야 해서, 무한 루프를 돌 수 있다.
                    // "/login"은 인증을 받기 위한 페이지이니, 로그인페이지에 permitAll을 하여 무한 루프로 돌지 않게 한다.
                    .permitAll()
                    // 로그인을 하고 갈 페이지가 없다면 메인페이지로 가라
                    // alwaysUse를 ture로 하면 유저 페이지 접근하여 로그인을 해도 무조건 "/"인 메인페이지로 간다.
                    // alwaysUse를 false로 하면 유저 페이지 접근하여 로그인 하면 해당 url로 요청이 가서 컨트롤러가 그것에 맞게 응답한다.
                    .defaultSuccessUrl("/", false)
                    .failureUrl("/login-error")
                )
                // 로그아웃을 하면 로그인 페이지로 가는게 아니라 "/"인 메인페이지로 가게
                .logout(logout->logout.logoutSuccessUrl("/"))
                .exceptionHandling(exception -> exception.accessDeniedPage("/access-denied"))
                ;
    }

  @Override
  public void configure(WebSecurity web) throws Exception {
    // 웹리소스는 security filter가 걸리지 않게 ignore 처리 해준다.
      web.ignoring()
        .requestMatchers(
            PathRequest.toStaticResources().atCommonLocations()
        )
        ;
  }

  // USER와 ADMIN 사용자 등록
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
            .inMemoryAuthentication()
            .withUser(
                User.withDefaultPasswordEncoder()
                        .username("user1")
                        .password("1111")
                        .roles("USER")
            ).withUser(
                User.withDefaultPasswordEncoder()
                          .username("admin")
                          .password("2222")
                          .roles("ADMIN")
    );
  }
}
