# ping_scan

Aplicativo Windows para monitorear dispositivos por ping.

La version actual integra el icono PING SCAN dentro del ejecutable y usa un tema oscuro tecnologico con acentos cyan/magenta para el dashboard.
La interfaz reacomoda encabezados, filtros, botones y tarjetas cuando la ventana cambia de tamano.
El ejecutable usa `app_icon.ico` como icono de archivo, ventana y barra de tareas.

## Uso rapido

1. Abra `ping_scan.exe`.
2. Use `Importar` para cargar un listado `.csv`, `.txt`, `.tsv` o `.xlsx`.
3. Las columnas reconocidas son:
   - `Nombre` o `Camara`
   - `IP`
   - `Tipo`
   - `Ubicacion` / `Sitio` opcional
   - `Afiliacion` opcional
   - `Tecnologia`
4. La estructura recomendada es: `Nombre`, `IP`, `Tipo`, `Ubicacion`, `Afiliacion`, `Tecnologia`.
5. En `Tipo` puede usar subtipos como `PTZ`, `F1`, `F2`, `LP 01`, `LP 02`, `Fija`.
6. En `Tecnologia` coloque valores como: `PMI`, `PMI de resguardo`, `LPR PMI`, `ARCO`, `REMOLQUE`.
7. El intervalo predeterminado es `3600` segundos, es decir, una revision cada hora.
8. La app inicia el monitoreo automaticamente si ya tiene dispositivos cargados. Tambien puede usar `Iniciar` para dejarla corriendo.
9. Use `Exportar CSV` para guardar resultados con estado, latencia, ultima revision y fallos.
10. Abra la pestana `Dashboard 3 dias` para ver disponibilidad por tecnologia, ubicacion/sitio, afiliacion o dispositivo/IP.

Para mejorar rendimiento con inventarios grandes, la tabla del Monitor no pinta todo el listado completo. Use `Buscar`, `Tipo`, `Ubicacion / sitio` y `Estado` para consultar dispositivos; la vista muestra hasta 500 coincidencias, pero el monitoreo sigue revisando todo el inventario cargado.
Use `Eliminar todo` para vaciar el inventario antes de cargar una nueva lista. Use `Reset historial` para limpiar el historial de pings.

El listado local se guarda automaticamente en `devices.xml`, junto al ejecutable.

El historial de pings se guarda en `history.dat`, un formato binario compacto para reducir peso y mejorar rendimiento. Si existe un `history.csv` anterior, la app lo lee y lo convierte al nuevo formato. La disponibilidad del dashboard se calcula con las muestras de los ultimos 3 dias: pings en linea sobre muestras totales. El tiempo activo mostrado es una aproximacion equivalente dentro de una ventana de 72 horas.

El archivo `history.dat` se reinicia automaticamente cada 5 dias. La fecha del ultimo reinicio se guarda en `history_reset.txt`; cuando se cumple el ciclo, la app borra las muestras anteriores y vuelve a generar historial con los nuevos pings.

Si no existe columna `Afiliacion`, la app la deriva desde `Nombre`. Ejemplo: `CHIH01-VVU-CDJU-030` se agrupa como afiliacion `VVU`.

En el dashboard puede:

- Escribir una ubicacion o sitio en `Ubicacion / sitio`, por ejemplo `Madera`.
- Escribir una afiliacion en `Afiliacion`, por ejemplo `VVU`.
- Escribir una IP o nombre de dispositivo en `IP / Dispositivo`.
- Cambiar `Agrupar` a `Ubicacion / sitio` o `Ubicacion/Tecnologia` para desglosar la disponibilidad por lugar operativo y tecnologia.
- Cambiar `Agrupar` a `Dispositivo/IP` para ver disponibilidad individual por dispositivo.
- El dashboard muestra un resumen fijo por ubicacion/sitio, aun cuando la grafica principal este agrupada por tecnologia u otra categoria.
- Usar `Descargar reporte` para guardar un PDF horizontal con el mismo diseno visual del dashboard y sus filtros actuales.

El dashboard toma la tecnologia desde la columna `Tecnologia`, por ejemplo:

- `PMI de resguardo` se agrupa como `PMI de resguardo`.
- `LPR PMI` se agrupa como `LPR`.
- `ARCO` se agrupa como `Arco`.
- `REMOLQUE` se agrupa como `Remolque`.
