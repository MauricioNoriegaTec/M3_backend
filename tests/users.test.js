jest.mock('../db', () => ({
  poolConnect: Promise.resolve(),
  sql: {},
  pool: { request: jest.fn() }
}));

const request = require('supertest');
const express = require('express');
const usersRouter = require('../routes/users');

const app = express();
app.use(express.json());
app.use('/api/users', usersRouter);

describe('POST /api/users', () => {
  it('should return 400 if required fields are missing', async () => {
    const res = await request(app)
      .post('/api/users')
      .send({ email: 'test@example.com' });
    expect(res.statusCode).toBe(400);
  });

  // Add more tests as needed, e.g., for duplicate users, etc.
});
