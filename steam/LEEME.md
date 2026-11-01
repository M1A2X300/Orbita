# Preparación para Steam (Windows)

`Preparar-Paquete.ps1` crea una carpeta de contenido y plantillas SteamPipe usando el App ID y el Depot ID asignados a tu aplicación en Steamworks:

```powershell
.\Preparar-Paquete.ps1 -AppId "TU_APP_ID" -DepotId "TU_DEPOT_ID"
```

El contenido queda en `content\`; `app_build.vdf` y `depot_build.vdf` son las configuraciones que se pueden usar con SteamCMD después de revisar los datos de Steamworks. No ejecutes una publicación con identificadores de ejemplo. El script excluye la base de datos, las pruebas y `tools\`, donde está el control local privado del servidor. La contraseña del administrador se guarda fuera del proyecto, en el perfil local de Windows, y nunca se copia al depot.

Para probarlo como juego externo en Steam, agrega `Iniciar Orbita en Steam.bat` como juego que no es de Steam. La computadora necesita Python 3 con el lanzador `pyw` y Microsoft Edge o Google Chrome instalados. El iniciador mantiene abierta la sesión del lanzador hasta que se cierra el juego.

## Antes de venderlo en la tienda

Este paquete es una preparación inicial, no un instalador autónomo listo para clientes. Aún depende de Python y de un navegador instalado, no incorpora Steamworks (logros, overlay integrado o identidad de Steam), y necesita los App ID/Depot ID reales y una cuenta Steamworks para publicarse. No incluyas `orbita.db`, credenciales SMTP, archivos de configuración privados ni copias de seguridad en un depot.
