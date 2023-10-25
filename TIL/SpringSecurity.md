# 🌐 What Spring Security do?

- 인증과 인가
- 일반적인 해킹 공격으로부터 보호 (CSRF, 세션 고정 등)

# 🌐 Spring Security 동작의 핵심 =⇒ Filter

![webcontext](https://user-images.githubusercontent.com/95271588/277607128-9d103374-0630-4e39-a1dc-c9851c5347e0.png)


- 하지만 Filter는 서블릿 기술이라서 Spring bean으로 등록해 쓰지못하는데 어떻게 Spring 내부에서 Filter를 다루는 것이 가능할까?
    - **해당 설명은 DelegatingFilterProxy 등장 이전 (Spring 1.2 이전)**
        - 참고 ) Spring이라면 DelegatingFilterProxy를 사용해야하지만 SpringBoot를 사용하면 DelegatingFilterProxy도 사용 안해도 된다.

# 🌐 Spring Security Architecture

## 1️⃣ Spring Security’s Servlet support is based on Servlet `Filter`s

![arch1](https://user-images.githubusercontent.com/95271588/277607425-e8a02dc1-191d-485f-8fe3-3d27ae586781.png)

## 2️⃣ DelegatingFilterProxy

![arch2](https://user-images.githubusercontent.com/95271588/277607488-a9f7bcf9-1e94-44f6-bc4d-44034eb34189.png)

- Another benefit of `DelegatingFilterProxy` is that it allows delaying looking `Filter` bean instances. This is important because the container needs to register the  instances before the container can startup. However, Spring typically uses a `ContextLoaderListener` to load the Spring Beans which will not be done until after the  instances need to be registered.
- 동작 순서
    1. Filter 구현체가 스프링 빈으로 등록된다.
    2. Servlet Context가 Filter 구현체를 갖는 DelegatingFilterProxy를 생성한다. (`@ConditionalOnBean`)
    3. ServletContext가 DelegatingFilterProxy를 서블릿 컨테이너에 필터로 등록한다.
    4. 요청이 오면 DelegatingFilterProxy가 필터 구현체에게 요청을 위임하여 필터 처리를 진행한다.

## 3️⃣ FilterChainProxy

![arch3](https://user-images.githubusercontent.com/95271588/277607547-cbf5d92e-f190-4290-9ea1-eb5a0c69e41c.png)

Spring Security’s Servlet support is contained within `FilterChainProxy`.  is a special `Filter` provided by Spring Security that allows delegating to many  instances through `[SecurityFilterChain](https://docs.spring.io/spring-security/reference/5.8/servlet/architecture.html#servlet-securityfilterchain)`. Since  is a Bean, it is typically wrapped in a [DelegatingFilterProxy](https://docs.spring.io/spring-security/reference/5.8/servlet/architecture.html#servlet-delegatingfilterproxy).

## 4️⃣ SecurityFilterChain

![arch4](https://user-images.githubusercontent.com/95271588/277607604-985a99eb-e726-49d6-8c44-29f8ba447972.png)

![arch5](https://user-images.githubusercontent.com/95271588/277607649-583afc22-2fdf-4dc6-9888-82a43e5220e3.png)

### `FilterChainProxy` 를 쓰는 것에 대한 장점

1. First, it provides a starting point for all of Spring Security’s Servlet support. For that reason, if you are attempting to troubleshoot Spring Security’s Servlet support, adding a debug point in `FilterChainProxy` is a great place to start. — Spring Security의 시작 지점을 알려준다.
2. Second, since `FilterChainProxy` is central to Spring Security usage it can perform tasks that are not viewed as optional. — 반드시 해야 하는 작업들을 할 수 있다.
    1. it clears out the `SecurityContext` to avoid memory leaks
    2. It also applies Spring Security’s `[HttpFirewall](https://docs.spring.io/spring-security/reference/5.8/servlet/exploits/firewall.html#servlet-httpfirewall)` to protect applications against certain types of attacks.
3. it provides more flexibility in determining when a `SecurityFilterChain` should be invoked. — 여러개의 Security Filter Chain이 있을 때 어떤 것을 넣을지 알려준다.

# 🌐 Config

## WebSecurity

- `WebSecurityCustomizer`를 통해 `Spring Security`를 적용하지 않을 리소스를 설정한다.
- `WebSecurityCustomizer` 는 함수형 인터페이스
    
    ```java
    @FunctionalInterface
    public interface WebSecurityCustomizer {
    
    	/**
    	 * Performs the customizations on {@link WebSecurity}.
    	 * @param web the instance of {@link WebSecurity} to apply to customizations to
    	 */
    	void customize(WebSecurity web);
    
    }
    
    // web 파라미터 : 함수형 인터페이스에서 기본 제공
    ```
    

# 🌐 Annotations

## `@EnableWebSecurity`

- 어노테이션은 스프링 시큐리티를 활성화하고 웹 보안 설정을 구성하는 데 사용됩니다.
- `@EnableWebSecurity` 어노테이션은 자동으로 Spring Security filter chain을 생성하고 웹 보안을 활성화 합니다.

### 기능

- 웹 보안 활성화 : 스프링 시큐리티의 필터 체인이 동작하여 요청을 인가하고 인증합니다.
- Spring security 구성 : 스프링 시큐리티 구성을 위한 `WebSecurityConfigurer` Bean을 생성합니다. 구성 클래스에서 `configure()`메서드를 오버라이딩 하여 웹 보안 설정을 구성할 수 있습니다.
- 다양한 보안 기능 추가 : 폼 기반 인증, 로그인 페이지 구성, 권한 설정 등의 다양한 보안기능 사용가능

# 🌐 WebSecurity vs HttpSecurity

### WebSecurity

- `antMatchers`에 파라미터로 넘겨주는 endpoints는 Spring Security Filter Chain을 거치지 않기 때문에 **'인증' , '인가' 서비스가 모두 적용되지 않는다.**
    - ant 인 이유는 Apache Ant project에서 따왔다고 한다. url 매칭 시 Ant Pattern을 이용하기 때문. ( [ant pattern 참고1](https://velog.io/@hjhearts/AntPattern-%EC%A0%95%EB%A6%AC)   [ant pattern 참고2](https://jaimemin.tistory.com/1442) )
- 또한 **Security Context를 설정하지 않고**, Security Features(Secure headers, CSRF protecting 등)가 사용되지 않는다.
- Cross-Site-Scripting(XSS), content-sniffing에 대한 endpoints 보호가 제공되지 않는다.
- 일반적으로 로그인 페이지, public 페이지 등 **인증, 인가 서비스가 필요하지 않은 endpoint에 사용**한다.
- 아래의 경우처럼 WebSecurity, HttpSecurity에 모두 설정을 한 경우 **WebSecurity가 HttpSecurity보다 우선적으로 고려**되기 때문에 HttpSecurity에 인가 설정은 무시된다.
    
    ```java
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
            .antMatchers("/publics/**");
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/publics/**").hasRole("USER") // no effect
            .anyRequest().authenticated();
    }
    ```
    

- `configure(HttpSecurity)` allows configuration of web-based security at a *resource level*, based on a selection match - e.g. The example below restricts the URLs that start with `/admin/` to users that have *ADMIN role*, and declares that any other URLs need to be *successfully authenticated.*

### HttpSecurity

- `antMatchers`에 있는 endpoint에 대한 '인증'을 무시한다.
- **Security Filter Chain에서 요청에 접근할 수 있기 때문**에(요청이 security filter chain 거침) 인증, 인가 서비스와 Secure headers, CSRF protection 등 같은 Security Features 또한 사용된다.
- 취약점에 대한 보안이 필요할 경우 HttpSecurity 설정을 사용해야 한다.
- `configure(WebSecurity)` is used for configuration settings that *impact global security* (ignore resources, set debug mode, reject requests by implementing a custom firewall definition). For example, the following method would cause any request that starts with `/resources/` to be *ignored for authentication* purposes.

# 🌐 Etc

## `HandlerMappingIntrospector`

- Spring MVC가 컨트롤러를 찾을 때 쓰는 같은 pattern Matchfing을 SpringSecurity에서 쓰기위해 만든 것
- SpringSecurity 이외에 다른 목적으로 쓰면 overhead of resolving the handler for a request 발생

# 🌐 Reference

https://devuna.tistory.com/59

https://kimchanjung.github.io/programming/2020/07/02/spring-security-02/[https://nahwasa.com/entry/스프링부트-Spring-Security-기본-세팅-스프링-시큐리티](https://nahwasa.com/entry/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-Spring-Security-%EA%B8%B0%EB%B3%B8-%EC%84%B8%ED%8C%85-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0)

[https://velog.io/@gkdud583/HttpSecurity-WebSecurity의-차이](https://velog.io/@gkdud583/HttpSecurity-WebSecurity%EC%9D%98-%EC%B0%A8%EC%9D%B4)

https://stackoverflow.com/questions/56388865/spring-security-configuration-httpsecurity-vs-websecurity

https://hoonzi-text.tistory.com/121

https://docs.spring.io/spring-security/reference/5.8/servlet/architecture.html

[https://velog.io/@younghoondoodoom/Spring-Security에-대해서-알아보자동작과정편](https://velog.io/@younghoondoodoom/Spring-Security%EC%97%90-%EB%8C%80%ED%95%B4%EC%84%9C-%EC%95%8C%EC%95%84%EB%B3%B4%EC%9E%90%EB%8F%99%EC%9E%91%EA%B3%BC%EC%A0%95%ED%8E%B8)

https://dveamer.github.io/backend/SpringBootAutoConfiguration.html

https://mangkyu.tistory.com/221

[https://www.inflearn.com/questions/116025/강의-하시면서-사용하는-resolving-이란-단어는-어떤-의미인가요](https://www.inflearn.com/questions/116025/%EA%B0%95%EC%9D%98-%ED%95%98%EC%8B%9C%EB%A9%B4%EC%84%9C-%EC%82%AC%EC%9A%A9%ED%95%98%EB%8A%94-resolving-%EC%9D%B4%EB%9E%80-%EB%8B%A8%EC%96%B4%EB%8A%94-%EC%96%B4%EB%96%A4-%EC%9D%98%EB%AF%B8%EC%9D%B8%EA%B0%80%EC%9A%94)