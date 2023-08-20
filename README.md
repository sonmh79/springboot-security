# Introduce
Spring Boot Security Project with JWT Token

# Version
- Java 11
- Springboot 2.7.14

# Directory Tree
```
.
├── HELP.md
├── build
├── build.gradle
├── gradle
├── gradlew
├── gradlew.bat
├── out 
├── settings.gradle
└── src
    ├── main
    │   ├── generated
    │   ├── java
    │   │   └── com
    │   │       └── example
    │   │           └── sstest
    │   │               ├── SstestApplication.java
    │   │               ├── auth
    │   │               │   └── domain
    │   │               │       ├── AppProperties.java
    │   │               │       ├── PrincipalDetails.java
    │   │               │       └── RestAuthenticationEntryPoint.java
    │   │               ├── config
    │   │               │   ├── CorsConfig.java
    │   │               │   ├── JwtConfig.java
    │   │               │   └── SecurityConfig.java
    │   │               ├── controller
    │   │               │   ├── MemberController.java
    │   │               │   ├── data
    │   │               │   │   ├── Data.java
    │   │               │   │   ├── LoginData.java
    │   │               │   │   └── ReissuedAccessTokenData.java
    │   │               │   ├── reponse
    │   │               │   │   └── ResponseDTO.java
    │   │               │   └── request
    │   │               │       └── LoginTestReq.java
    │   │               ├── domain
    │   │               │   └── Member.java
    │   │               ├── exception
    │   │               │   ├── ControllerExceptionHandler.java
    │   │               │   ├── JwtExpiredException.java
    │   │               │   ├── MemberNotFoundException.java
    │   │               │   ├── TokenValidFailedException.java
    │   │               │   └── UnAuthorizedException.java
    │   │               ├── jwt
    │   │               │   ├── AuthToken.java
    │   │               │   ├── AuthTokenProvider.java
    │   │               │   ├── TokenAccessDeniedHandler.java
    │   │               │   └── TokenAuthenticationFilter.java
    │   │               ├── repository
    │   │               │   └── MemberRepository.java
    │   │               ├── service
    │   │               │   └── MemberService.java
    │   │               └── util
    │   │                   ├── CookieUtil.java
    │   │                   └── HeaderUtil.java
    │   └── resources
    │       ├── application.yml
    │       ├── static
    │       └── templates
    └── test
        └── java
            └── com
                └── example
                    └── sstest
                        └── SstestApplicationTests.java
```
