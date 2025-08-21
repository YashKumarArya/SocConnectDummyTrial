import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(process.cwd(), '.env') });

export const config = {
  port: Number(process.env.PORT || 3000),
  kafka: {
    brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
    clientId: process.env.KAFKA_CLIENT_ID || 'security-alert-backend'
  },
  clickhouseUrl: process.env.CLICKHOUSE_URL || 'http://localhost:8123'
};

export type Config = typeof config;
