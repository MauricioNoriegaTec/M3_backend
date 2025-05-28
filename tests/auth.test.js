jest.mock('../db', () => ({
  poolConnect: Promise.resolve(),
  sql: {},
  pool: { request: jest.fn() }
}));

const request = require('supertest');
const express = require('express');
const authRouter = require('../routes/auth');

const app = express();
app.use(express.json());
app.use('/api/auth', authRouter);

describe('POST /api/auth/login', () => {
  it('should return 400 if email or password is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: '' });
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toMatch(/required/);
  });

  // You can add more tests with a mock DB or skip DB-dependent tests
});
