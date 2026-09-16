// BLACKOUT 2026
// Las banderas activas ya no se almacenan en este archivo.
// El servidor genera una bandera individual y estable por operador/pregunta
// mediante HMAC en server.js. Esto evita reutilizar las banderas antiguas.
export const FLAG_HASHES = {};
