/**
 * Environment Configuration for FastAPI Backend Integration
 * Production-ready configuration management
 */

export interface SecurityServiceConfig {
  baseUrl: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  apiKey?: string;
  credentials?: {
    username: string;
    password: string;
  };
}

export interface EnvironmentConfig {
  api: {
    baseUrl: string;
    timeout: number;
  };
  services: {
    gvm: SecurityServiceConfig;
  };
  websocket: {
    url: string;
    reconnectInterval: number;
  };
  development: {
    mockData: boolean;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
  };
}

const getEnvironmentConfig = (): EnvironmentConfig => {
  const isProduction = window.location.hostname !== 'localhost';
  const isDevelopment = !isProduction;

  return {
    api: {
      baseUrl: isDevelopment ? 'http://localhost:3001' : '/api',
      timeout: 30000,
    },
    services: {
      gvm: {
        baseUrl: isDevelopment ? 'http://localhost:9392' : 'https://gvm-api.yourdomain.com',
        timeout: 30000,
        retryAttempts: 2,
        retryDelay: 3000,
        credentials: {
          username: 'admin',
          password: 'admin', // In production, this would come from secure storage
        },
      },
    },
    websocket: {
      url: isDevelopment ? 'ws://localhost:3001/ws' : 'wss://your-fastapi-backend.com/ws',
      reconnectInterval: 5000,
    },
    development: {
      mockData: isDevelopment,
      logLevel: isDevelopment ? 'debug' : 'info',
    },
  };
};

export const config = getEnvironmentConfig();

// Production-ready logging with different levels
export const logger = {
  debug: (...args: any[]) => {
    if (config.development.logLevel === 'debug') {
      console.log('[DEBUG]', ...args);
    }
  },
  info: (...args: any[]) => {
    if (['debug', 'info'].includes(config.development.logLevel)) {
      console.info('[INFO]', ...args);
    }
  },
  warn: (...args: any[]) => {
    if (['debug', 'info', 'warn'].includes(config.development.logLevel)) {
      console.warn('[WARN]', ...args);
    }
  },
  error: (...args: any[]) => {
    console.error('[ERROR]', ...args);
  },
};