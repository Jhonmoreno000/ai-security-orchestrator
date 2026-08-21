# Política de Seguridad

## Divulgación Responsable de Vulnerabilidades

AI Security Orchestrator se compromete a garantizar la seguridad de sus usuarios y la plataforma. Si descubres una vulnerabilidad, por favor sigue el proceso de divulgación responsable descrito a continuación.

---

## Proceso de Reporte

### 1. No publiques la vulnerabilidad públicamente

No crees un issue público en GitHub ni compartas los detalles de la vulnerabilidad en foros, redes sociales o cualquier otro medio público.

### 2. Reporta de forma privada

Envía un correo electrónico a: **morenopossojhonanderson313@gmail.com**

Incluye la siguiente información en tu reporte:

- **Descripción**: Descripción clara y concisa de la vulnerabilidad
- **Pasos para reproducir**: Instrucciones detalladas para replicar el problema
- **Impacto potencial**: Evaluación del impacto de la vulnerabilidad
- **Versión afectada**: Versión o commit específico donde se encontró
- **Sugerencia de corrección**: Si es posible, incluye una propuesta de fix
- **Evidencia**: Screenshots, logs o payloads de prueba (sin ejecutar exploits reales)

### 3. Respuesta esperada

| Fase | Tiempo estimado |
|------|-----------------|
| Confirmación de recepción | 24-48 horas |
| Evaluación de severidad | 3-5 días |
| Corrección (dependiendo de severidad) | 7-30 días |
| Publicación del parche + Creditos | Después de la corrección |

---

## Severidad

Utilizamos la escala CVSS v3.1 para clasificar vulnerabilidades:

| Severidad | CVSS | Descripción |
|-----------|------|-------------|
| **Crítica** | 9.0 - 10.0 | Ejecución remota de código, acceso total al sistema |
| **Alta** | 7.0 - 8.9 | Pérdida significativa de datos o disponibilidad |
| **Media** | 4.0 - 6.9 | Acceso parcial a datos o funcionalidad |
| **Baja** | 0.1 - 3.9 | Información limitada expuesta |

---

## Lo que NO califica como vulnerabilidad

- Configuraciones por defecto que el usuario debe cambiar (ej: `POSTGRES_PASSWORD` en `.env`)
- Vulnerabilencias en dependencias de terceros sin vector de explotación demostrable
- Issues de rendimiento sin impacto en seguridad
- Problemas de UX o documentación

---

## Responsabilidades del Reporter

- Actuar de buena fe y no acceder a datos de otros usuarios
- No ejecutar exploits que puedan causar daño real a la plataforma
- No modificar o eliminar datos existentes durante la prueba
- Respetar los tiempos de corrección antes de divulgar públicamente

---

## Responsabilidades del Proyecto

- Responder a todos los reportes dentro del tiempo estimado
- Mantener al reporter informado del progreso
- Reconocer públicamente la contribución (con permiso del reporter)
- No tomar acciones legales contra reporters que sigan este proceso

---

## Seguridad de la Plataforma

### Medidas de protección implementadas

- **Aislamiento Docker**: Los escáneres se ejecutan en contenedores aislados sin acceso al socket Docker
- **Política de Herramientas**: Allowlist de escáneres permitidos (`zap`, `nuclei`, `semgrep`, `trivy`)
- **Sanitización de IA**: Detección y enmascaramiento de secrets antes de enviarlos a Ollama
- **Variables de Entorno**: Secrets nunca se commitean al repositorio
- **CORS Configurado**: Restricción de orígenes permitidos
- **Pydantic Validation**: Validación estricta de todos los inputs

### Infraestructura de seguridad

- PostgreSQL con credenciales configuradas via `.env`
- Redis sin autenticación (solo accesible en red interna Docker)
- Backend sin acceso al Docker socket de host
- Frontend servido via nginx con proxy inverso

---

## Contacto

- **Email**: morenopossojhonanderson313@gmail.com
- **GitHub Issues**: Solo para bugs generales, NO para vulnerabilidades de seguridad
- **GitHub Security Advisories**: Habilitado para reportes privados

---

## Agradecimientos

Agradecemos a los investigadores de seguridad que contribuyan a mejorar la plataforma de forma responsable. Los nombres de los reporters serán incluidos en la sección de créditos (con su permiso).
