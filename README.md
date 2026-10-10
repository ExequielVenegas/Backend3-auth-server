# Servidor de autorización

Autentica los clientes técnicos Web, Móvil y Cajero mediante OAuth2 client_credentials y emite JWT firmados con audiencias y permisos diferenciados.

## Participación en el proyecto

| Aspecto | Función |
|---|---|
| Entrada | Credenciales del cliente y scopes solicitados |
| Salida | JWT y claves públicas de verificación |
| Ejecución | HTTPS localhost:9000 |

## Flujo completo

Los CSV se procesan localmente con Spring Batch y sus resultados se guardan en MySQL. Los datos históricos permanecen disponibles; las asociaciones revisadas permiten crear cuentas modernas con trazabilidad al archivo de origen.

El cliente obtiene un JWT en Auth Server y accede por HTTPS a su BFF (Web, Móvil o Cajero). El BFF valida el token y sus permisos, adapta la respuesta y descubre los servicios mediante Eureka. Customer administra perfiles; Account administra cuentas, saldos y movimientos; Payment administra órdenes de pago.

Para una operación monetaria, el BFF envía la orden a Payment, que guarda la orden y su outbox. Kafka en AWS transporta el comando hasta Account. Account aplica los movimientos en una transacción de MySQL y publica el resultado mediante su outbox. Payment consume el resultado y la consulta del BFF informa APLICADO o RECHAZADO. La clave de idempotencia evita repetir el efecto de una misma operación. El flujo de solicitudes de estado de cuenta se publica directamente desde BFF Web hacia Kafka y lo consume Account.

Config Server centraliza propiedades y Resilience4j limita los fallos en llamadas HTTP. Docker Compose ejecuta los servicios locales; MySQL y el batch permanecen en el PC. AWS aloja únicamente Kafka, en modo KRaft.

Los clientes OAuth representan canales de demostración; no son sesiones personales de clientes bancarios.
