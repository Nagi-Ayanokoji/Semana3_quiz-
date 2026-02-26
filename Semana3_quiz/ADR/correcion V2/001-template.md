# ADR-001: Refactorización del módulo de autenticación por violaciones críticas de seguridad y Clean Code
#Jesus David Bernal Gonzalez
## Contexto

El sistema `logincaos` es una aplicación web en Java con Spring Boot que expone endpoints de registro y login de usuarios. Durante la auditoría de código y las pruebas funcionales realizadas en la Semana 3, se identificaron doce problemas, de los cuales seis son de riesgo alto e impactan directamente la seguridad de los usuarios y la estabilidad del sistema en producción.

Durante las pruebas funcionales se confirmó que el endpoint de login retorna el hash MD5 de la contraseña directamente en la respuesta JSON. Esto se verificó haciendo un POST a `/login?u=admin&p=12345`, que devolvió `"hash": "827ccb0eea8a706c4c34a16891f84e7b"` — un valor que cualquier herramienta en línea puede revertir a `12345` en menos de un segundo. Adicionalmente, el código fuente de `UserRepository.java` construye las consultas SQL pegando directamente el input del usuario como texto, lo que representa una vulnerabilidad de SQL Injection confirmada en el análisis estático del código. Se intentó explotar esta vulnerabilidad con `admin'--` desde Postman, PowerShell y Git Bash, y aunque los clientes codificaron la comilla automáticamente impidiendo la explotación, la vulnerabilidad permanece latente en el código para cualquier atacante que controle directamente la petición HTTP.

A nivel de mantenibilidad, el código usa nombres de variables de una sola letra en todos los archivos, mezcla responsabilidades dentro de `AuthService`, no cierra las conexiones a la base de datos después de usarlas, y tiene atributos públicos en el modelo `User`. Todo esto afecta al equipo de desarrollo, que tiene dificultad para leer y mantener el código, y a los usuarios finales, cuya seguridad está comprometida por el uso de MD5 y la exposición de datos sensibles en las respuestas.

---

## Decisión

### 1. Reemplazar `Statement` por `PreparedStatement` para eliminar SQL Injection

En `UserRepository.java`, tanto `findByUsername` (línea 19) como `save` (línea 32) construyen consultas concatenando strings. Se reemplazará este enfoque por `PreparedStatement` con parámetros (`?`), de modo que el motor de base de datos separe siempre el código SQL de los datos del usuario.

**Código actual (vulnerable):**
```java
// UserRepository.java línea 19
String q = "select username, email, password from users where username = '" + u + "'";
ResultSet r = s.executeQuery(q);

// UserRepository.java línea 32
String q = "insert into users (username, email, password) values ('" + u.username + "', '" + u.email + "', '" + u.password + "')";
```

**Código corregido:**
```java
try (Connection connection = DriverManager.getConnection(url, user, pass);
     PreparedStatement ps = connection.prepareStatement(
         "select username, email, password from users where username = ?")) {
    ps.setString(1, username);
    ResultSet result = ps.executeQuery();
}
```

### 2. Reemplazar MD5 por BCrypt para el hashing de contraseñas

El método `md5()` en `AuthService.java` se eliminará y se usará `BCryptPasswordEncoder` de Spring Security. Las pruebas confirmaron que el hash MD5 actual (`827ccb0eea8a706c4c34a16891f84e7b`) puede revertirse trivialmente. BCrypt aplica un factor de costo configurable que hace que cada intento de fuerza bruta sea computacionalmente costoso, e incorpora un "salt" automático que garantiza que dos usuarios con la misma contraseña tengan hashes distintos.

**Código actual (inseguro):**
```java
// AuthService.java línea 52
private String md5(String s) throws Exception {
    MessageDigest d = MessageDigest.getInstance("MD5");
    byte[] b = d.digest(s.getBytes());
    StringBuilder r = new StringBuilder();
    for (byte c : b) {
        r.append(String.format("%02x", c));
    }
    return r.toString();
}
```

**Código corregido:**
```java
private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

// Para guardar la contraseña:
String hashedPassword = passwordEncoder.encode(rawPassword);

// Para verificar en el login:
boolean matches = passwordEncoder.matches(rawPassword, storedHash);
```

### 3. Eliminar datos sensibles de las respuestas HTTP y de los logs

El campo `hash` se eliminará de la respuesta del endpoint `/login`. Las pruebas demostraron que este campo se retornaba incluso en intentos de login fallidos, exponiendo el hash de cualquier contraseña ingresada. Adicionalmente, se eliminarán los `System.out.println` que imprimen emails en los logs.

**Código actual (expone datos sensibles):**
```java
// AuthService.java línea 24-27
res.put("ok", true);
res.put("user", c.username);
res.put("hash", hp);  // ← expone el hash al cliente

// AuthService.java línea 24 y 40
System.out.println("enviando email a " + c.email);  // ← expone email en logs
```

**Código corregido:**
```java
res.put("ok", true);
res.put("user", user.getUsername());
// el hash NO se incluye en la respuesta
// los logs no incluyen datos personales
```

### 4. Mover las credenciales de base de datos a variables de entorno

Las credenciales hardcodeadas en `UserRepository.java` (líneas 13-15) se moverán a variables de entorno del sistema operativo.

**Código actual (inseguro):**
```java
// UserRepository.java líneas 13-15
private String url = "jdbc:postgresql://db:5432/logincaos";
private String user = "admin";
private String pass = "admin123";
```

**Código corregido:**
```java
// En application.properties:
// spring.datasource.url=${DB_URL}
// spring.datasource.username=${DB_USER}
// spring.datasource.password=${DB_PASS}

@Value("${spring.datasource.url}")
private String url;
```

### 5. Refactorizar nombres, separar responsabilidades y fortalecer validación de contraseña

Se renombrarán todas las variables con nombres descriptivos, se extraerá la lógica de hashing a una clase `PasswordEncoder` separada aplicando SRP, se añadirán getters y setters en `User`, y se reforzará la validación de contraseña.

**Código actual (nombres sin significado y validación débil):**
```java
// AuthController.java - nombres de una sola letra
public ResponseEntity<Map<String, Object>> login(@RequestParam String u, @RequestParam String p)

// AuthService.java línea 37 - validación insuficiente
if (p.length() > 3) {  // acepta "1234", "aaaa", etc.

// User.java - atributos públicos sin encapsulamiento
public String username;
public String email;
public String password;
```

**Código corregido:**
```java
// Nombres descriptivos
public ResponseEntity<Map<String, Object>> login(@RequestParam String username, @RequestParam String password)

// Validación robusta
if (password.length() >= 8 && password.matches(".*[a-zA-Z].*") && password.matches(".*[0-9].*")) {

// Encapsulamiento correcto
private String username;
private String email;
private String password;
// + getters y setters
```

---

## Consecuencias

### Positivas
- Se elimina el riesgo de SQL Injection, la vulnerabilidad más crítica encontrada en el código.
- Las contraseñas quedan protegidas con BCrypt, resistente a ataques de fuerza bruta y tablas de búsqueda.
- El hash de la contraseña deja de aparecer en las respuestas HTTP, reduciendo la superficie de exposición confirmada en las pruebas.
- El código se vuelve legible y mantenible: cualquier desarrollador nuevo puede entender qué hace cada variable y cada método.
- Las conexiones a la base de datos se cierran correctamente, previniendo agotamiento de recursos en producción.
- Las credenciales de la base de datos quedan fuera del repositorio, mejorando la seguridad operacional.
- La validación de contraseñas rechaza valores débiles como `1234`, que actualmente son aceptados.

### Riesgos y costos
- La refactorización requiere tiempo estimado de 1 a 2 días para un desarrollador con experiencia.
- Al cambiar el algoritmo de hashing de MD5 a BCrypt, los usuarios existentes no podrán iniciar sesión hasta implementar una migración (re-hashear en el primer login exitoso o forzar reseteo de contraseña).
- Existe riesgo de regresiones si no se tienen pruebas automatizadas previas, por lo que se recomienda añadir tests unitarios antes de refactorizar.
- Mover credenciales a variables de entorno requiere coordinar con el equipo de infraestructura para configurar los ambientes correctamente.

---

## Alternativas consideradas

### Alternativa 1: Reescribir el módulo de autenticación desde cero con Spring Security completo y JWT
Se evaluó descartar todo el código actual y construir el módulo usando Spring Security con autenticación basada en tokens JWT. Se descartó porque el alcance del proyecto es pequeño y la refactorización incremental resuelve los problemas críticos con menor riesgo de introducir nuevos errores. Reescribir desde cero tomaría significativamente más tiempo, requeriría pruebas exhaustivas de integración y podría introducir nuevas vulnerabilidades si no se configura correctamente.

### Alternativa 2: Corregir solo los problemas de seguridad sin refactorizar nombres ni estructura
Se consideró hacer el mínimo cambio posible: solo aplicar `PreparedStatement` y BCrypt, dejando los nombres de variables de una letra y la estructura actual. Se descartó porque la deuda técnica en nombres y estructura dificulta mantener las correcciones en el futuro. Un código con variables llamadas `u`, `c` y `r` hace más probable que un desarrollador introduzca nuevas vulnerabilidades por no entender qué está modificando. La refactorización de nombres y responsabilidades tiene un costo bajo y un valor alto a largo plazo, por lo que no tiene sentido posponerla.
