# Spring-Boot-JWT-Authentication-with-Role-Based-Authorization
Simple sistema de autenticación seguro usando JSON Web Tokens (JWT) con roles que permite un CRUD usuarios
Aquí tienes el README completo para tu proyecto de autenticación con Spring Boot y JWT, siguiendo los principios SOLID:

## Estructura del Proyecto (SOLID)

```
src/main/java/
└── com/velasquez/authentication/demo/
├── config/
│ ├── ApplicationConfig.java
│ └── SecurityConfig.java
├── controller/
│ ├── AuthenticationController.java
│ └── UserController.java
├── dto/
│ ├── AuthenticationRequest.java
│ ├── AuthenticationResponse.java
│ └── RegisterRequest.java
├── entity/
│ ├── Role.java
│ └── Users.java
├── repository/
│ └── UserRepository.java
├── security/
│ ├── JwtAuthenticationFilter.java
│ └── JwtService.java
├── service/
│ ├── AuthenticationService.java
│ └── UserServices.java
└── DemoApplication.java
```
**Leyenda:**
- 📁 `config/`: Configuraciones de la aplicación
- 📁 `controller/`: Controladores REST
- 📁 `dto/`: Objetos de Transferencia de Datos
- 📁 `entity/`: Entidades del dominio
- 📁 `repository/`: Interfaces de acceso a datos
- 📁 `security/`: Componentes de seguridad
- 📁 `service/`: Lógica de negocio
- 🚀 `DemoApplication.java`: Clase principal

## Dependencias del Proyecto

### Dependencias Principales

| Grupo ID                     | Artifact ID                   | Versión  | Descripción |
|------------------------------|-------------------------------|----------|-------------|
| `org.springframework.boot`   | `spring-boot-starter-data-jpa` | -        | Integración con JPA/Hibernate para acceso a datos |
| `org.springframework.boot`   | `spring-boot-starter-security` | -        | Spring Security para autenticación y autorización |
| `org.springframework.boot`   | `spring-boot-starter-web`      | -        | Construcción de aplicaciones web REST |

### Dependencias de JWT (JSON Web Tokens)

| Grupo ID       | Artifact ID    | Versión | Uso |
|----------------|----------------|---------|-----|
| `io.jsonwebtoken` | `jjwt-api`     | 0.11.5  | API para creación/validación de JWT |
| `io.jsonwebtoken` | `jjwt-impl`    | 0.11.5  | Implementación runtime de JJWT |
| `io.jsonwebtoken` | `jjwt-jackson` | 0.11.5  | Soporte para serialización Jackson |

### Otras Dependencias

```xml
<!-- Base de datos MySQL -->
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <scope>runtime</scope>
</dependency>

<!-- Lombok para reducción de código boilerplate -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
```

### Plugins usados

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <configuration>
        <source>${java.version}</source>
        <target>${java.version}</target>
        <!-- Configuración especial para Lombok -->
        <annotationProcessorPaths>
            <path>
                <groupId>org.projectlombok</groupId>
                <artifactId>lombok</artifactId>
                <version>${lombok.version}</version>
            </path>
        </annotationProcessorPaths>
    </configuration>
</plugin>
```
## Configuración de la Aplicación

### 1. Configuración de Base de Datos (MySQL)
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/jwt_auth
    username: root
    password: root
    driver-class-name: com.mysql.cj.jdbc.Driver
```

**Variables:**
- `url`: Conexión a la base de datos MySQL
- `username/password`: Credenciales de acceso
- `driver-class-name`: Controlador JDBC para MySQL

### 2. Configuración JPA/Hibernate
```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.MySQL8Dialect
```

**Opciones clave:**
- `ddl-auto: create-drop` → Crea y elimina tablas al iniciar/detener (solo desarrollo)
- `show-sql: true` → Muestra SQL en consola
- `format_sql: true` → Formatea el SQL para mejor legibilidad
- `dialect` → Optimizado para MySQL 8+

### 3. Configuración JWT
```yaml
jwt:
  secret-key: c2d112bff0bb34f4be5d9b8553270e26f9c9e09a18c40e885a5d961259e45d53
  expiration: 86400000 # 24 horas
```

**Seguridad:**
- `secret-key`: Clave HMAC-SHA256 para firmar tokens
- `expiration`: Tiempo de vida del token (ms)

## Endpoints Principales

| Método | Endpoint               | Descripción                      | Acceso       |
|--------|------------------------|----------------------------------|--------------|
| POST   | /api/v1/auth/register  | Registrar nuevo usuario          | Público      |
| POST   | /api/v1/auth/login     | Autenticación (obtener JWT)      | Público      |
| GET    | /api/v1/users          | Listar todos usuarios            | ROLE_ADMIN   |
| GET    | /api/v1/users/{id}     | Obtener usuario por ID           | ROLE_USER/ADMIN |

---
## Configuración del proyecto


### 1. Entities

#### `Users.java`
```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class Users implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(nullable = false)
    private String firstName;
    @Column(nullable = false)
    private String lastName;
    @Column(unique = true, nullable = false)
    private String email;
    @Column(nullable = false)
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    // Implementación de UserDetails...
}
```

**Función**: 
- Representa la tabla de usuarios en la base de datos
- Implementa `UserDetails` para integración con Spring Security
- Usa anotaciones JPA para mapeo objeto-relacional
- Incluye validación de campos obligatorios

#### `Role.java`
```java
public enum Role {
    ROLE_USER, ROLE_ADMIN
}
```

**Función**: 
- Define los roles disponibles en el sistema
- Usa el prefijo `ROLE_` requerido por Spring Security

---

### 2. Repository

#### `UserRepository.java`
```java
@Repository
public interface UserRepository extends JpaRepository<Users, Integer> {
    Optional<Users> findByEmail(String email);
}
```

**Función**:
- Proporciona operaciones CRUD automáticas
- Incluye método personalizado para buscar por email
- Sigue el principio de **Segregación de Interfaces (SOLID)** al tener solo métodos necesarios

---

### 3. Services

#### `UserServices.java`
```java
@Service
@RequiredArgsConstructor
public class UserServices {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public List<Users> getAllUsers() { ... }
    public Users getUserById(Integer id) { ... }
    public Users createUser(Users user) { ... }
    public Users updateUser(Integer id, Users userDetails) { ... }
    public void deleteUser(Integer id) { ... }
}
```

**Responsabilidades**:
- Lógica de negocio para gestión de usuarios
- Encriptación de contraseñas
- Validación de reglas de negocio
- Sigue el **Principio de Responsabilidad Única (SOLID)**

#### `AuthenticationService.java`
```java
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    
    public AuthenticationResponse register(RegisterRequest request) { ... }
    public AuthenticationResponse authenticate(AuthenticationRequest request) { ... }
}
```

**Responsabilidades**:
- Registro de nuevos usuarios
- Autenticación y generación de JWT
- Delegación de responsabilidades a otros componentes

---

### 4. Controllers

#### `AuthenticationController.java`
```java
@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(...) { ... }
    
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(...) { ... }
}
```

**Endpoints**:
- `POST /api/v1/auth/register`: Registro de usuarios
- `POST /api/v1/auth/authenticate`: Autenticación (login)

#### `UserController.java`
```java
/**
 * Controlador para gestión de usuarios.
 * Sigue el principio de Segregación de Interfaces (SOLID)
 */
@RestController
@RequestMapping("/api/v1/users")
@PreAuthorize("hasRole('ROLE_ADMIN')")
public class UserController {
    private final UserServices userService;
    
    @GetMapping
    public List<Users> getAllUsers() { ... }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public Users getUserById(...) { ... }
    
    // Otros endpoints CRUD...
}
```

**Seguridad**:
- Control de acceso basado en roles
- Anotaciones `@PreAuthorize` para autorización granular

---

### 5. Seguridad (Config)

#### `SecurityConfig.java`
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtAuthenticacionFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

**Configuraciones clave**:
- Deshabilita CSRF (común en APIs stateless)
- Permite acceso público a endpoints de autenticación
- Configura política de sesiones STATELESS
- Registra el filtro JWT

#### `ApplicationConfig.java`
```java
@Configuration
public class ApplicationConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

**Componentes creados**:
- UserDetailsService personalizado
- Proveedor de autenticación
- Codificador de contraseñas BCrypt

#### `JwtAuthenticacionFilter.java`
```java
@Component
public class JwtAuthenticacionFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(...) {
        // 1. Extraer token del header
        // 2. Validar token
        // 3. Cargar UserDetails
        // 4. Establecer autenticación en SecurityContext
    }
}
```

**Flujo**:
1. Intercepta cada solicitud
2. Extrae y valida JWT
3. Establece autenticación en contexto de seguridad

#### `JwtService.java`
```java
@Service
public class JwtService {
    @Value("${jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    public String extractUserName(String token){...}
    public <T> T extractClaim){...}
    public List<String> extractRoles){...}
    public String generateToken(UserDetails userDetails){...}
    public String generateToken){...}
    public boolean isTokenValid(String token){...}
    private boolean isTokenExpired(String token){...}
    private Date extractExpiration(String token){...}
    private Claims extractAllClaims(String token){...}
    private Key getSignInKey(){...}
}
```

**Funcionalidades**:
- Generación de tokens JWT
- Validación de tokens
- Extracción de claims
- Configurable mediante properties

---

## Tabla de Conceptos Clave

| Concepto               | Explicación                                  | Relación con SOLID |
|------------------------|---------------------------------------------|--------------------|
| Inversión de Dependencias | Los componentes dependen de abstracciones | Principio D (DIP) |
| Single Responsibility  | Cada clase tiene una única responsabilidad | Principio S (SRP) |
| JWT Authentication     | Token-based stateless authentication       | -                  |
| Spring Security        | Framework para autenticación/autorización  | -                  |
| BCryptPasswordEncoder  | Encriptación segura de contraseñas         | -                  |
| Repository Pattern     | Abstracción para acceso a datos            | Principio I (ISP)  |

## Cómo Ejecutar el Proyecto

1. **Requisitos**:
   - Java 17+
   - Maven
   - Base de datos configurada (añadir config en `application.properties`)

2. **Endpoints principales**:
   - `POST /api/v1/auth/register` - Registrar nuevo usuario
   - `POST /api/v1/auth/authenticate` - Obtener token JWT
   - `GET /api/v1/users` - Listar usuarios (requiere rol ADMIN)

3. **Ejemplo de registro**:
```json
POST /api/v1/auth/register
{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "password": "password123",
    "role": "ROLE_ADMIN"
}
```
**Observaciones:**
- Al enviar el JSON, escribir correctamente los atributos
- Si no se envia el role, se registra como ROLE_USER


4. **Ejemplo de autenticación**:
```json
POST /api/v1/auth/authenticate
{
    "email": "john@example.com",
    "password": "password123"
}
```
