# Auditoría de Código — Semana 3 Quiz
#Jesus David Bernal Gonzalez 
## Tabla de Hallazgos

| # | Descripción del problema | Archivo | Línea aprox. | Principio violado | Riesgo |
|---|--------------------------|---------|--------------|-------------------|--------|
| 1 | La consulta SQL de búsqueda de usuario se construye concatenando el input directamente, permitiendo SQL Injection | `UserRepository.java` | 19 | Seguridad — SQL Injection | **Alto** |
| 2 | El INSERT también concatena datos sin protección, permitiendo SQL Injection al registrarse | `UserRepository.java` | 32 | Seguridad — SQL Injection | **Alto** |
| 3 | Las contraseñas se guardan con MD5, un algoritmo roto que puede revertirse con tablas de búsqueda públicas | `AuthService.java` | 52 | Seguridad — hashing débil | **Alto** |
| 4 | El login retorna el hash MD5 de la contraseña en la respuesta HTTP, exponiendo información sensible | `AuthService.java` | 26 | Seguridad — exposición de datos | **Alto** |
| 5 | Las credenciales de la base de datos están escritas directamente en el código fuente | `UserRepository.java` | 13–15 | Seguridad — hardcoded credentials | **Alto** |
| 6 | Variables con nombres de una sola letra sin significado: `u`, `p`, `c`, `r`, `s`, `q`, `x` | `AuthService.java`, `UserRepository.java`, `AuthController.java` | Múltiples | Clean Code — Naming | **Medio** |
| 7 | Cada consulta abre una nueva conexión a la base de datos y nunca la cierra (sin try-with-resources) | `UserRepository.java` | 17, 30 | Clean Code — gestión de recursos | **Alto** |
| 8 | `AuthService` hace login, registro y hashing todo junto, violando el principio de responsabilidad única | `AuthService.java` | Completo | SOLID — SRP | **Medio** |
| 9 | Comentarios que solo repiten lo obvio: `// este metodo hace el login` no aporta información | `AuthService.java` | 18, 35 | Clean Code — comentarios inútiles | **Bajo** |
| 10 | Los atributos de `User` son públicos, rompiendo el encapsulamiento | `User.java` | 4–6 | Clean Code — encapsulamiento | **Medio** |
| 11 | La validación de contraseña solo verifica más de 3 caracteres — demasiado permisiva | `AuthService.java` | 37 | Seguridad — validación débil | **Medio** |
| 12 | Se imprime el email del usuario en los logs del servidor, exponiendo datos personales | `AuthService.java` | 24, 40 | Seguridad — exposición de datos en logs | **Medio** |

---

## Evidencia de código — Problemas críticos

### Hallazgo 1 y 2 — SQL Injection (`UserRepository.java` líneas 19 y 32)

**Código actual (vulnerable):**
```java
// Línea 19 - búsqueda de usuario
String q = "select username, email, password from users where username = '" + u + "'";
ResultSet r = s.executeQuery(q);

// Línea 32 - registro de usuario
String q = "insert into users (username, email, password) values ('" + u.username + "', '" + u.email + "', '" + u.password + "')";
s.executeUpdate(q);
```

**Cómo debería quedar:**
```java
// Búsqueda segura con PreparedStatement
PreparedStatement ps = conn.prepareStatement("select username, email, password from users where username = ?");
ps.setString(1, username);
ResultSet result = ps.executeQuery();

// Registro seguro con PreparedStatement
PreparedStatement ps = conn.prepareStatement("insert into users (username, email, password) values (?, ?, ?)");
ps.setString(1, user.getUsername());
ps.setString(2, user.getEmail());
ps.setString(3, user.getPassword());
ps.executeUpdate();
```

---

### Hallazgo 3 — Hashing débil con MD5 (`AuthService.java` línea 52)

**Código actual (inseguro):**
```java
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

**Cómo debería quedar:**
```java
// Con BCrypt de Spring Security
private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

// Para guardar:
String hashedPassword = passwordEncoder.encode(rawPassword);

// Para verificar:
boolean matches = passwordEncoder.matches(rawPassword, storedHash);
```

---

### Hallazgo 4 — Exposición del hash en la respuesta (`AuthService.java` línea 26)

**Código actual (expone el hash):**
```java
res.put("ok", true);
res.put("user", c.username);
res.put("hash", hp);  // ← NUNCA debería retornarse esto
```

**Cómo debería quedar:**
```java
res.put("ok", true);
res.put("user", user.getUsername());
// El hash NO se incluye en la respuesta
```

---

### Hallazgo 5 — Credenciales hardcodeadas (`UserRepository.java` líneas 13-15)

**Código actual (inseguro):**
```java
private String url = "jdbc:postgresql://db:5432/logincaos";
private String user = "admin";
private String pass = "admin123";
```

**Cómo debería quedar:**
```java
// En application.properties:
// spring.datasource.url=${DB_URL}
// spring.datasource.username=${DB_USER}
// spring.datasource.password=${DB_PASS}

@Value("${spring.datasource.url}")
private String url;
```

---

### Hallazgo 7 — Conexiones no cerradas (`UserRepository.java` líneas 17 y 30)

**Código actual (fuga de recursos):**
```java
Connection c = DriverManager.getConnection(url, user, pass);
Statement s = c.createStatement();
// ... nunca se llama c.close() ni s.close()
```

**Cómo debería quedar:**
```java
try (Connection connection = DriverManager.getConnection(url, user, pass);
     PreparedStatement ps = connection.prepareStatement(query)) {
    // la conexión se cierra automáticamente al salir del bloque
}
```

---

### Hallazgo 11 — Validación débil de contraseña (`AuthService.java` línea 37)

**Código actual (insuficiente):**
```java
if (p.length() > 3) {  // acepta "1234", "aaaa", etc.
```

**Cómo debería quedar:**
```java
if (password.length() >= 8 && password.matches(".*[a-zA-Z].*") && password.matches(".*[0-9].*")) {
    // mínimo 8 caracteres, con al menos una letra y un número
```

---

## Pruebas Funcionales

### ✅ Prueba 1 — Login válido

**Comando ejecutado en Postman:**
```
POST http://localhost:8080/login?u=admin&p=12345
```

**Respuesta obtenida:**
```json
{
  "ok": true,
  "user": "admin",
  "hash": "827ccb0eea8a706c4c34a16891f84e7b"
}
```

**Análisis:**
La respuesta incluyó el campo `hash` con el MD5 de la contraseña del usuario. Este dato no debería retornarse jamás al cliente. El hash `827ccb0eea8a706c4c34a16891f84e7b` corresponde a la contraseña `12345` y puede verificarse en segundos usando tablas de búsqueda públicas disponibles en internet. Cualquier persona que intercepte esta respuesta obtiene información suficiente para comprometer la cuenta. La respuesta debería limitarse únicamente a confirmar si el login fue exitoso, sin exponer ningún dato derivado de la contraseña.

---

### ⚠️ Prueba 2 — SQL Injection

**Comando intentado en Postman, PowerShell y Git Bash:**
```
POST http://localhost:8080/login?u=admin'--&p=cualquiercosa
```

**Respuesta obtenida:**
```json
{
  "ok": false,
  "hash": "9dd4e461268c8034f5c8564e155c67a6"
}
```

**Análisis:**
El ataque no se ejecutó exitosamente desde los clientes utilizados (Postman, PowerShell y Git Bash) porque todos codificaron automáticamente la comilla simple `'` antes de enviarla al servidor, modificando el payload. Sin embargo, al revisar el código fuente de `UserRepository.java` línea 19, la consulta SQL se construye así:

```java
String q = "select username, email, password from users where username = '" + u + "'";
```

Si el input llegara sin codificar, la consulta resultante sería:
```sql
SELECT * FROM users WHERE username = 'admin'--'
```

El `--` comentaría el resto de la consulta, eliminando la verificación de contraseña y permitiendo acceder como cualquier usuario sin conocer su clave. La vulnerabilidad existe en el código y es crítica. El hecho de que no se haya podido explotar desde estos clientes no significa que el servidor esté protegido — un atacante con control directo sobre la petición HTTP podría explotarla sin dificultad.

---

### ✅ Prueba 3 — Registro con contraseña débil

**Intento 1 — contraseña de 3 caracteres:**
```
POST http://localhost:8080/register?u=test&p=123&e=test@test.com
```
**Respuesta:**
```json
{
  "ok": false
}
```

**Intento 2 — contraseña de 4 caracteres:**
```
POST http://localhost:8080/register?u=test2&p=1234&e=test2@test.com
```
**Respuesta:**
```json
{
  "ok": true,
  "user": "test2"
}
```

**Análisis:**
La validación rechazó `123` (3 caracteres) pero aceptó `1234` (4 caracteres). Esta validación no es suficiente. Una contraseña segura debería tener mínimo 8 caracteres, combinar letras mayúsculas, minúsculas, números y símbolos, y no ser una secuencia obvia. La regla actual (`p.length() > 3`) da una falsa sensación de seguridad: existe una validación pero no protege a los usuarios en la práctica, ya que contraseñas extremadamente débiles como `1234` o `aaaa` son aceptadas sin problema.
