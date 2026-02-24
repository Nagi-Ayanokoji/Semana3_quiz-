# ADR-001: Refactorización del módulo de autenticación por violaciones críticas de seguridad y Clean Code
#Jesus David Bernal Gonzalez

## Contexto

El sistema `logincaos` es una aplicación web en Java con Spring Boot que expone endpoints de registro y login de usuarios. Durante la auditoría de código y las pruebas funcionales realizadas en la Semana 3, se identificaron doce problemas, de los cuales seis son de riesgo alto e impactan directamente la seguridad de los usuarios y la estabilidad del sistema en producción.

Durante las pruebas funcionales se confirmó que el endpoint de login retorna el hash MD5 de la contraseña directamente en la respuesta JSON. Esto se verificó haciendo un POST a `/login?u=admin&p=12345`, que devolvió `"hash": "827ccb0eea8a706c4c34a16891f84e7b"` — un valor que cualquier herramienta en línea puede revertir a `12345` en menos de un segundo. Adicionalmente, el código fuente de `UserRepository.java` construye las consultas SQL pegando directamente el input del usuario como texto, lo que representa una vulnerabilidad de SQL Injection confirmada en el análisis estático del código. Se intentó explotar esta vulnerabilidad con `admin'--` desde Postman, PowerShell y Git Bash, y aunque los clientes codificaron la comilla automáticamente impidiendo la explotación, la vulnerabilidad permanece latente en el código para cualquier atacante que controle directamente la petición HTTP.

A nivel de mantenibilidad, el código usa nombres de variables de una sola letra en todos los archivos, mezcla responsabilidades dentro de `AuthService`, no cierra las conexiones a la base de datos después de usarlas, y tiene atributos públicos en el modelo `User`. Todo esto afecta al equipo de desarrollo, que tiene dificultad para leer y mantener el código, y a los usuarios finales, cuya seguridad está comprometida por el uso de MD5 y la exposición de datos sensibles en las respuestas.

---

## Decisión

### 1. Reemplazar `Statement` por `PreparedStatement` para eliminar SQL Injection

En `UserRepository.java`, tanto `findByUsername` (línea 19) como `save` (línea 32) construyen consultas concatenando strings. Se reemplazará este enfoque por `PreparedStatement` con parámetros (`?`), de modo que el motor de base de datos separe siempre el código SQL de los datos del usuario. Esta solución es el estándar de la industria, tiene soporte nativo en JDBC y elimina completamente el vector de ataque sin necesidad de librerías adicionales. Las conexiones también se envolverán en bloques `try-with-resources` para garantizar que se cierren automáticamente.

### 2. Reemplazar MD5 por BCrypt para el hashing de contraseñas

El método `md5()` en `AuthService.java` se eliminará y se usará `BCryptPasswordEncoder` de Spring Security. Las pruebas confirmaron que el hash MD5 actual (`827ccb0eea8a706c4c34a16891f84e7b`) puede revertirse trivialmente. BCrypt aplica un factor de costo configurable que hace que cada intento de fuerza bruta sea computacionalmente costoso, e incorpora un "salt" automático que garantiza que dos usuarios con la misma contraseña tengan hashes distintos.

### 3. Eliminar datos sensibles de las respuestas HTTP y de los logs

El campo `hash` se eliminará de la respuesta del endpoint `/login`. Las pruebas demostraron que este campo se retornaba incluso en intentos de login fallidos, exponiendo el hash de cualquier contraseña ingresada. La respuesta solo indicará si el acceso fue exitoso. Adicionalmente, se eliminarán los `System.out.println` que imprimen emails en los logs, reemplazándolos por logs que no expongan datos personales.

### 4. Mover las credenciales de base de datos a variables de entorno

Las credenciales hardcodeadas en `UserRepository.java` (líneas 13-15) se moverán a `application.properties` y se leerán desde variables de entorno del sistema operativo. Esto evita que el repositorio de código contenga secretos y permite que cada entorno use sus propias credenciales sin modificar el código fuente.

### 5. Refactorizar nombres, separar responsabilidades y fortalecer validación de contraseña

Se renombrarán todas las variables con nombres descriptivos (`username`, `password`, `connection`, `query`), se extraerá la lógica de hashing a una clase `PasswordEncoder` separada aplicando SRP, se añadirán getters y setters en `User` eliminando los atributos públicos, y se reforzará la validación de contraseña a un mínimo de 8 caracteres con al menos una letra y un número (la prueba confirmó que `1234` era aceptado como contraseña válida).

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
