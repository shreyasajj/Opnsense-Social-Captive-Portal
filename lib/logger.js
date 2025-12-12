const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

const levels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3
};

const currentLevel = levels[LOG_LEVEL] ?? levels.info;

function log(level, ...args) {
  if (levels[level] <= currentLevel) {
    const timestamp = new Date().toISOString();
    console[level](`[${timestamp}] [${level.toUpperCase()}]`, ...args);
  }
}

module.exports = {
  error: (...args) => log('error', ...args),
  warn:  (...args) => log('warn', ...args),
  info:  (...args) => log('info', ...args),
  debug: (...args) => log('debug', ...args)
};