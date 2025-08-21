// Kafka producer/consumer setup (stub)
import { config } from '../config';

let started = false;
const produced: Array<{ topic: string; message: any }> = [];

export async function initKafka() {
  // initialise Kafka producer/consumer (dev stub)
  started = true;
  console.log('Kafka initialized with brokers', config.kafka.brokers);
}

export async function produce(topic: string, message: any) {
  if (!started) {
    throw new Error('Kafka not initialized');
  }
  const payload = { topic, message, timestamp: Date.now() };
  produced.push(payload);
  console.log('Produced to Kafka (stub):', topic, message);
  return true;
}

export function _getProduced() {
  return produced;
}
