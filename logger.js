const fs = require('fs');
const path = require('path');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const transport = new DailyRotateFile({
  filename: path.join(logDir, 'server-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
});

const humanReadableFormat = winston.format.printf(info => {
  const { timestamp, level } = info;
  const baseMessage =
    typeof info.message === 'object'
      ? JSON.stringify(info.message)
      : info.message || '';

  const { message: _msg, level: _lvl, timestamp: _ts, ...rest } = info;
  let metadata = { ...rest };

  const splat = info[Symbol.for('splat')];
  if (Array.isArray(splat)) {
    for (const entry of splat) {
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        metadata = { ...metadata, ...entry };
      }
    }
  }

  delete metadata[Symbol.for('splat')];

  const metaKeys = Object.keys(metadata);
  let metaString = '';
  if (metaKeys.length > 0) {
    try {
      metaString = ` ${JSON.stringify(metadata)}`;
    } catch (err) {
      metaString = ' [unserializable metadata]';
    }
  }

  return `${timestamp} [${level}] ${baseMessage}${metaString}`;
});

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    humanReadableFormat
  ),
  transports: [transport],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        humanReadableFormat
      ),
    })
  );
}

module.exports = logger;
