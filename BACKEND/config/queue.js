// FILE: cybershield-backend/config/queue.js
import { Queue } from 'bullmq';
import Redis from 'redis';

// Robustly parse REDIS_URL using the URL API
const redisUrl = (() => {
  try {
    return new URL(process.env.REDIS_URL || 'redis://localhost:6379');
  } catch (e) {
    return new URL('redis://localhost:6379');
  }
})();
const redisConnection = {
  host: redisUrl.hostname || 'localhost',
  port: parseInt(redisUrl.port, 10) || 6379,
  username: redisUrl.username || undefined,
  password: redisUrl.password || undefined,
};

// Create scan queue
export const scanQueue = new Queue('scan-jobs', {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 5000,
    },
    removeOnComplete: {
      count: 100,
      age: 24 * 3600, // 24 hours
    },
    removeOnFail: {
      count: 500,
      age: 7 * 24 * 3600, // 7 days
    },
  },
});

// Redis client for pub/sub (optional logging)
export const redisClient = Redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
});

redisClient.on('error', (err) => console.error('Redis Client Error:', err));
redisClient.on('connect', () => console.log('✅ Redis Connected'));

// Connect Redis client
(async () => {
  await redisClient.connect();
})();

export { redisConnection };