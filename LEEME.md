# Órbita en línea

El juego incluye un servidor en Python, una base de datos SQLite, acceso por código de un solo uso enviado por correo, historial de partidas y un ranking con las mejores puntuaciones.

## Probar en esta computadora

1. Instala Python 3 y Microsoft Edge o Google Chrome si aún no los tienes.
2. Haz doble clic en el acceso directo **Órbita** del escritorio (o en `Iniciar Orbita.vbs`). No abras `Iniciar Orbita.bat`: Windows muestra una terminal al ejecutar archivos `.bat`.
3. El iniciador abre el servidor de forma oculta y muestra solamente la ventana del juego. Al cerrar esa ventana o pulsar **Cerrar juego**, también se apaga el servidor.
4. Registra una cuenta con tu correo y el nombre público que aparecerá en el ranking. Escribe el código de verificación que recibirás por correo.

Para una sola ejecución de diagnóstico, inicia `Iniciar Orbita.bat --diagnostico`: la consola muestra los comandos del servidor y el navegador, además de la salida de sus procesos. Sin ese argumento, el inicio habitual sigue ocultando la consola.

El servidor crea `orbita.db` en esa carpeta y registra cada partida terminada, incluso si vuelves al menú o cierras el juego. Para recibir códigos, configura un proveedor SMTP mediante las variables de entorno indicadas en **Acceso por correo**. Sin SMTP configurado, el juego sigue disponible offline, pero no se pueden crear cuentas ni iniciar sesión por correo. No abras `index.html` directamente ni la dirección local en otra ventana: inicia el juego desde el acceso directo para que se apaguen juntos.

La sesión se conserva en este navegador mientras siga vigente (30 días en el servidor). Usa **Perfil** para cerrar sesión o cambiar de cuenta. Si no hay conexión de red al abrir el juego o el servidor no responde, se inicia una partida offline automáticamente. También puedes elegir **Jugar offline (sin guardar)** en cualquier momento. En ese modo, el puntaje, el récord y la partida no se guardan ni se envían al ranking.

## Abrir el juego en PC

Órbita está preparado para jugarse en una computadora con teclado y mouse. Inicia el juego con el acceso directo del escritorio; el iniciador abre una ventana dedicada y apaga el servidor al cerrarla. No incluye una app ni una instalación para celulares.

Para probarlo desde Steam como juego externo, agrega `steam\Iniciar Orbita en Steam.bat` a tu biblioteca. Requiere Python 3 y Edge o Chrome. La carpeta `steam` contiene una preparación inicial para SteamPipe; revisa `steam\LEEME.md`. La publicación en la tienda aún requiere App ID/Depot ID de Steamworks y empaquetar los runtimes para que el cliente no tenga que instalar Python y un navegador.

El control privado del servidor está en `tools\Control privado Orbita.bat`, fuera del paquete de Steam. Configura primero una contraseña local; se guarda como hash en tu perfil de Windows. Para apagar el servidor, el control solicita la contraseña y una confirmación. Después puedes volver a abrir el juego para iniciarlo otra vez. Solo administra el servidor que corre en esta PC; no apaga un servidor remoto.

La sesión se conserva en esta computadora mientras siga vigente (30 días en el servidor). Si no hay conexión al iniciar, se puede jugar offline, pero las cuentas y el ranking requieren que el servidor responda.

En los controles puedes escoger entre tres modelos de nave y cuatro colores. La música espacial sintetizada se activa desde **♫ Música** y recuerda tu preferencia en este navegador.

## Acceso por correo y datos

Las cuentas nuevas se verifican con un código de 8 dígitos, válido durante 10 minutos y para un solo uso. Si ya tenías una cuenta, usa **Vincular cuenta anterior**: confirma tu usuario y contraseña anteriores y verifica el nuevo correo. La migración conserva el nombre del ranking y las partidas guardadas. Los datos se almacenan en `orbita.db`; el acceso nuevo no solicita ni guarda una contraseña elegida por el usuario.

El proyecto no incluye un proveedor de correo ni envía códigos sin una configuración SMTP válida. Si falta esa configuración o el proveedor rechaza el envío, el juego muestra un error y no acepta el código. En el equipo local, configura las variables SMTP antes de iniciar el servidor; en un alojamiento, guárdalas como secretos/variables privadas del servicio y permite la salida al puerto SMTP elegido. No pongas credenciales en el código ni las envíes por el chat.

Configura un servicio SMTP antes de iniciar el servidor. No pongas estas credenciales en el código ni las compartas:

- `ORBITA_SMTP_HOST`: servidor SMTP del proveedor.
- `ORBITA_SMTP_PORT`: normalmente `587` para STARTTLS o `465` para TLS implícito.
- `ORBITA_SMTP_USERNAME` y `ORBITA_SMTP_PASSWORD`: credenciales SMTP del proveedor; déjalas ambas vacías solo si el proveedor permite retransmisión autenticada por red.
- `ORBITA_SMTP_FROM`: dirección remitente autorizada.
- `ORBITA_SMTP_SECURITY`: `starttls` (predeterminado) o `ssl`.
- `ORBITA_EMAIL_CODE_PEPPER`: secreto persistente de al menos 32 caracteres. En una instalación pública HTTPS es obligatorio; consérvalo fuera del código y no lo cambies al reiniciar, pues los códigos pendientes dejarían de validarse. En uso local, si falta, se genera uno nuevo al iniciar y los códigos pendientes dejan de funcionar al reiniciar.

El botón **Exportar mis partidas** descarga un `.xlsx` con las partidas de la cuenta que tiene la sesión activa, ordenadas por puntuación descendente. No incluye correos, contraseñas, códigos ni partidas de otras cuentas. Protege `orbita.db` y las copias de seguridad: contienen correos vinculados, cuentas e historial.

## Publicarlo en Internet

El código queda preparado, pero todavía no está publicado: esta carpeta no tiene un proveedor de alojamiento configurado. Para hacerlo accesible a otras personas, despliega `servidor.py`, `index.html` y la carpeta `icons` en un servicio que permita ejecutar Python. Configura `PORT` con el puerto asignado por el proveedor, `ORBITA_HOST=0.0.0.0` y `ORBITA_DATABASE` con la ruta de `orbita.db` dentro del almacenamiento persistente. Usa HTTPS en el dominio público y no compartas ni subas la base de datos de esta computadora.

### Railway

Los archivos `.python-version` y `requirements.txt` hacen que Railpack detecte la aplicación Python; `railway.json` define el comando de inicio y la comprobación de salud y deja que Railway seleccione automáticamente su builder actual. Para desplegarlo, conecta este repositorio de GitHub a un servicio de Railway y usa el proyecto Railway correspondiente. Añade un volumen persistente montado en `/data` y configura estas variables en **Variables** del servicio:

- `ORBITA_HOST`: `0.0.0.0`
- `ORBITA_DATABASE`: `/data/orbita.db`
- `ORBITA_PUBLIC_SCHEME`: `https`
- `ORBITA_EMAIL_CODE_PEPPER`: secreto persistente de al menos 32 caracteres
- `ORBITA_SMTP_HOST`, `ORBITA_SMTP_PORT`, `ORBITA_SMTP_USERNAME`, `ORBITA_SMTP_PASSWORD`, `ORBITA_SMTP_FROM` y `ORBITA_SMTP_SECURITY`: datos privados del proveedor de correo; usa `starttls` o `ssl` según el puerto y proveedor.

Railway asigna `PORT` automáticamente. Genera un dominio HTTPS para el servicio desde **Networking**. No guardes credenciales SMTP ni el secreto pepper en GitHub. Sin un volumen persistente se pueden perder las cuentas y partidas al reemplazar la instancia; sin SMTP no se pueden verificar cuentas ni iniciar sesión por correo.

Las cuentas anteriores conservan sus contraseñas con derivación PBKDF2; los códigos se guardan como hashes HMAC y vencen tras 10 minutos o cinco intentos fallidos. Las sesiones se almacenan como hashes. Cada partida online recibe un identificador de un solo uso y el servidor verifica que la puntuación no supere lo posible según el tiempo transcurrido desde su inicio. Aun así, la partida y su duración se calculan en el navegador: el servidor no puede demostrar que el jugador esquivó los meteoritos ni que la partida terminó por una colisión. No uses el ranking para premios ni como sistema antitrampas.

El servidor limita por IP y por correo los intentos de acceso, además de las consultas y escrituras; rechaza cargas JSON grandes o ambiguas, valida el origen y el tipo de contenido de las solicitudes que modifican datos, y envía una política CSP con nonces para los scripts y estilos del juego. También limita el aislamiento entre orígenes y, bajo HTTPS, activa HSTS. La sesión se entrega en una cookie `HttpOnly`, `SameSite=Strict` y, bajo HTTPS, `Secure` con prefijo `__Host-`; JavaScript no puede leer el token.

**Límites de seguridad:** `servidor.py` usa el servidor HTTP estándar de Python y no cifra conexiones por sí solo. En Internet, debe quedar detrás de un proxy o plataforma que termine TLS; configura allí HTTPS, `ORBITA_PUBLIC_SCHEME=https`, HSTS y límites de conexiones, conserva `Host` del dominio público y haz que el proxy sobrescriba `X-Forwarded-For`. Si configuras `ORBITA_TRUSTED_PROXIES` con las IP/CIDR exactas de ese proxy, el servidor solo usará esa cabecera para limitar intentos cuando la conexión venga de una IP confiable. No expongas directamente el servidor HTTP ni uses datos reales sin copias de seguridad protegidas. La puntuación se genera en el navegador; el servidor comprueba que coincida con la duración, pero no puede demostrar que una partida no fue manipulada. No uses el ranking para premios ni como registro antitrampas.
