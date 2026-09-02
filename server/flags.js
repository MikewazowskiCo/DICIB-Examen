// CTF flag definitions. Only hashes are exported for validation.
import crypto from 'node:crypto';
const h = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const make = (team, values) => values.map((answer, i) => ({ id: `${team}-${String(i + 1).padStart(2, '0')}`, hash: h(answer) }));

// Cada equipo sigue la misma ruta de dificultad. Las respuestas son distintas por equipo
// para evitar que compartir una captura resuelva automáticamente el reto de otro equipo.
// Las excepciones intencionales son el correo, la clave, la frase en guaraní y la pista final.
const build = (team) => [
  `FLAG{INICIO_${team}}`,
  `FLAG{${team}_BUSCA_EL_EVENTO}`,
  `FLAG{${team}_MIRA_LA_URI}`,
  `FLAG{${team}_FILTRA_HTTP}`,
  `FLAG{${team}_IDENTIFICA_EL_METODO}`,
  `FLAG{${team}_LOCALIZA_EL_HOST}`,
  `FLAG{${team}_IDENTIFICA_EL_ORIGEN}`,
  `FLAG{${team}_IDENTIFICA_EL_DESTINO}`,
  `FLAG{${team}_SIGUE_LA_CONEXION}`,
  `FLAG{${team}_BUSCA_EL_PARAMETRO}`,
  `FLAG{${team}_RECONSTRUYE_LA_PETICION}`,
  `FLAG{${team}_ENCUENTRA_EL_VALOR_OCULTO}`,
  `FLAG{${team}_SIGUE_LA_CADENA}`,
  'micorreoeswazowski@gmail.com',
  'JuniorTuPapa',
  `FLAG{${team}_REVISA_EL_CORREO}`,
  'Poyvi ha\'e Colombia, ryvy Paraguái.',
  `FLAG{${team}_RECONSTRUYE_EL_MENSAJE}`,
  `FLAG{${team}_BUSCA_LA_IDENTIDAD}`,
  `FLAG{${team}_ENCUENTRA_EL_PERFIL}`,
  `FLAG{${team}_SIGUE_LA_PISTA_FINAL}`,
  `FLAG{${team}_UBICA_EL_USUARIO}`,
  `FLAG{${team}_BUSCA_INSTAGRAM}`,
  `FLAG{${team}_CONFIRMA_MIKEVARGAX}`,
  'HACK THE WORLD'
];

export const FLAG_HASHES = Object.fromEntries(
  ['ALFA', 'BRAVO', 'CHARLIE', 'DELTA'].map(team => [team, make(team, build(team))])
);
