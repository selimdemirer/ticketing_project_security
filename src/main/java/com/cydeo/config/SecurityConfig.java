package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    private final SecurityService securityService;
    private final AuthSuccessHandler authSuccessHandler;

    public SecurityConfig(SecurityService securityService, AuthSuccessHandler authSuccessHandler) {
        this.securityService = securityService;
        this.authSuccessHandler = authSuccessHandler;
    }

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//
//        List<UserDetails> userList = new ArrayList<>();
//
//        userList.add(
//                new User("mike", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")))
//        );
//
//        userList.add(
//                new User("ozzy", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER")))
//        );
//
//        return new InMemoryUserDetailsManager(userList);
//
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        return http
                .authorizeRequests()
//                .antMatchers("/user/**").hasRole("ADMIN") // ROLE_ prefix is automatically added.
                .antMatchers("/user/**").hasAuthority("Admin") // 7. Certain roles should be able to see certain pages. We can use .hasRole and .hasAuthority to define roles. Whatever I put in the parenthesis needs to match roles in DB. Since I use "Admin" in roles table, I use .hasAuthority not .hasRole
                .antMatchers("/project/**").hasAuthority("Manager")
                .antMatchers("/task/employee/**").hasAuthority("Employee")
                .antMatchers("/task/**").hasAuthority("Manager")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE","ADMIN")
//                .antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE") "**" meaning is everything includes under that end point
                .antMatchers( // 6. These ant matchers means something related with the pages. Why did I put here? Because everyone should be able to access "/" and "/login" page. I want everything under images, css, html should be available
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                ).permitAll()
                .anyRequest().authenticated()
                .and()
//                .httpBasic()
                .formLogin() // 1. I want to introduce my own validation form to spring
                    .loginPage("/login")// 2. This is the representation of my login page. Basically wherever that form.. /login controller is gonna give me that view..
                    // .defaultSuccessUrl("/welcome")// 3. Whenever login information is successfully done, basically whenever user authenticated with the correct user name and password, this is the page I am gonna land it
                    .successHandler(authSuccessHandler)
                    .failureUrl("/login?error=true")// 4. If user put the wrong information I want to navigate to this url
                    .permitAll()// 5. This form login should be accessible by everyone I don't need put security on here, because everyone should be able to access login page
                .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // Can
                    .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                    .tokenValiditySeconds(120) // How long time security will remind you
                    .key("cydeo")
                    .userDetailsService(securityService)
                .and()
                .build();
    }



}
