package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author li
 * @Date 11/15/22 8:11 PM
 * @Version 1.0
 * 描述 ：security配置类
 * 名称：SecurityConfig
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        //忽略静态资源
        web.ignoring().antMatchers("/resources/**");
    }

    //主要做权限认证，对认证做处理
    //主要组件：AuthenticationManager，认证的核心接口
    //AuthenticationManagerBuilder：构建AuthenticationManager对象的工具
    //ProviderManager：AuthenticationManager接口的默认实现类

    //AuthenticationManagerBuilder->构建构建AuthenticationManager对象的工具对象->ProviderManager是AuthenticationManager接口的默认实现类
    // ，并且持有一组AuthenticationProvider

    /**这是认证部分
     *
     *登录时，security先捕获账户密码 走authenticate方法
     * 都是基于filter)过滤器javaee
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内置的认证规则
       // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));

       //自定义认证规则
        //AuthenticationProvider: ProviderManager持有一组AuthenticationProvider，每个AuthenticationProvider负责一种认证
        //委托模式：ProviderManager将认证委托给AuthenticationProvider实现账号密码认证
       auth.authenticationProvider(new AuthenticationProvider() {
           //Authentication：用于封装认证信息的接口，不同的实现类代表不同类型的认证信息(都是基于filter)
           @Override
           public Authentication authenticate(Authentication authentication) throws AuthenticationException {

               String username = authentication.getName();
               String password = (String) authentication.getCredentials();

               User user = userService.findUserByName(username);
               if (user==null){
                   throw new UsernameNotFoundException("账号不存在");
               }
               password = CommunityUtil.md5(password+user.getSalt());
               if (!user.getPassword().equals(password)){
                   throw new BadCredentialsException("密码不正确");
               }
               //principal:主要信息；credentials：证书；authorities：权限
               return new UsernamePasswordAuthenticationToken(user,user.getPassword(),user.getAuthorities());
           }
            //当前AuthenticationProvider支持哪种类型的认证
           @Override
           public boolean supports(Class<?> aClass) {

               //UsernamePasswordAuthenticationToken:Authentication接口的常用实现类，代表该接口类型认证用的是账号密码认证
               return UsernamePasswordAuthenticationToken.class.equals(aClass);
           }
       });

    }
    /**
     * 这是认证和授权的配置部分
     * 如果不重写所有页面请求都拦截，这就是为了避开登录页面
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //登录相关配置
        http.formLogin()
                .loginPage("/loginpage")
                //登录的接口此时会调用上面的认证方法authcation
                .loginProcessingUrl("/login")
                //如果成功的化可以跳转到首页
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath()+"/index");
                    }
                })
                //失败转发到登录页面，不使用重定向方式，使用转发的方式
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        request.setAttribute("error",e.getMessage());
                        request.getRequestDispatcher("/loginpage").forward(request,response);
                    }
                });
         //退出的相关配置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath()+"/index");
                    }
                });
        // 授权配置
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER","ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")
                //什么权限都没有时走这个路径
                .and().exceptionHandling().accessDeniedPage("/denied");
        // 增加Filter,处理验证码，在登陆之前的这个UsernamePasswordAuthenticationFilter加入
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                if (request.getServletPath().equals("/login")) {
                    String verifyCode = request.getParameter("verifyCode");
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")) {
                        request.setAttribute("error", "验证码错误!");
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                        return;
                    }
                }
                // 让请求继续向下执行.
                filterChain.doFilter(request, response);
            }
        }, UsernamePasswordAuthenticationFilter.class);

        // 记住我
        http.rememberMe()
                //这里是将用户信息记录到内存，可以记录到数据库和redis中自己实现这个接口
                .tokenRepository(new InMemoryTokenRepositoryImpl())
                .tokenValiditySeconds(3600 * 24)
                .userDetailsService(userService);


    }
    /**重定向：
     * 如果请求服务器时服务器没有什么返回数据，并且洗完服务器返回一下刷新的查询页面，
     * 例如你进行一个删除操作，但是想删完跳转到首页列表，这两个请求间没有什么必然的联系那么使用重定向。
     * 请求转发：
     * 浏览器向服务器发送请求，服务器内A组件无法满足客户端请求，需要B组件来协助，需要把request数据转发给B使用，然后B返回给客户端，需要服务端两个业务共同完成一个请求
     */
}
