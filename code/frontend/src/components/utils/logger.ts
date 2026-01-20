type LogLevel = 'debug' | 'info' | 'warn' | 'error';

type LoggerOptions = {
  level?: LogLevel;
  namespace?: string;
};

const levelWeight: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const defaultLevel: LogLevel =
  typeof process !== 'undefined' && process.env.NODE_ENV === 'production'
    ? 'info'
    : 'debug';

const shouldLog = (requested: LogLevel, current: LogLevel) =>
  levelWeight[requested] >= levelWeight[current];

const formatNamespace = (ns?: string) => (ns ? `[${ns}]` : '');

export function createLogger(options: LoggerOptions = {}) {
  const { namespace, level = defaultLevel } = options;

  return {
    debug: (...args: unknown[]) => {
      if (shouldLog('debug', level))
        console.debug(formatNamespace(namespace), ...args);
    },
    info: (...args: unknown[]) => {
      if (shouldLog('info', level))
        console.info(formatNamespace(namespace), ...args);
    },
    warn: (...args: unknown[]) => {
      if (shouldLog('warn', level))
        console.warn(formatNamespace(namespace), ...args);
    },
    error: (...args: unknown[]) => {
      if (shouldLog('error', level))
        console.error(formatNamespace(namespace), ...args);
    },
  };
}
