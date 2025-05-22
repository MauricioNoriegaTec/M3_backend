const express = require('express');
const router = express.Router();
const { poolConnect, sql, pool } = require('../db');
const bcrypt = require('bcrypt');
const authMiddleware = require('../middleware/auth');

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - username
 *         - email
 *         - password
 *       properties:
 *         user_id:
 *           type: integer
 *           description: The auto-generated ID of the user
 *         username:
 *           type: string
 *           description: The user's username
 *         email:
 *           type: string
 *           description: The user's email
 *         name:
 *           type: string
 *           description: The user's first name
 *         lastname:
 *           type: string
 *           description: The user's last name
 *       example:
 *         username: johndoe
 *         email: john@example.com
 *         name: John
 *         lastname: Doe
 */

/**
 * @swagger
 * /api/users:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user in the system
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               lastname:
 *                 type: string
 *             required:
 *               - username
 *               - email
 *               - password
 *     responses:
 *       201:
 *         description: User created successfully
 *       400:
 *         description: Invalid request data
 *       409:
 *         description: Username or email already exists
 *       500:
 *         description: Server error
 */
// Public route - Register user
router.post('/', async (req, res) => {
  const { username, email, password, name, lastname } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send('username, email, and password are required');
  }

  try {
    await poolConnect;

    // Hash password before inserting
    const saltRounds = 10;
    const password_hash = await bcrypt.hash(password, saltRounds);

    await pool.request()
      .input('username', sql.NVarChar(50), username)
      .input('email', sql.NVarChar(255), email)
      .input('password_hash', sql.NVarChar(255), password_hash)
      .input('name', sql.NVarChar(100), name || null)
      .input('lastname', sql.NVarChar(100), lastname || null)
      .query(`INSERT INTO noriusers (username, email, password_hash, name, lastname)
              VALUES (@username, @email, @password_hash, @name, @lastname)`);

    res.status(201).send('User created');
  } catch (err) {
    // Handle duplicate username/email
    if (err.originalError && err.originalError.info && err.originalError.info.number === 2627) {
      return res.status(409).send('Username or email already exists');
    }
    res.status(500).send(err.message);
  }
});

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users
 *     description: Retrieve a list of all users. Requires authentication.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
// Protected routes - Apply auth middleware to all routes below
router.use(authMiddleware);

// GET all users (protected)
router.get('/', async (req, res) => {
  try {
    await poolConnect;
    const result = await pool.request().query('SELECT user_id, username, email, name, lastname FROM noriusers');
    res.json(result.recordset);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get a user by ID
 *     description: Retrieve a specific user by ID. Requires authentication.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     responses:
 *       200:
 *         description: User data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
// GET user by ID (protected)
router.get('/:id', async (req, res) => {
  try {
    await poolConnect;
    const result = await pool.request()
      .input('id', sql.Int, req.params.id)
      .query('SELECT user_id, username, email, name, lastname FROM noriusers WHERE user_id = @id');

    if (result.recordset.length === 0) return res.status(404).send('User not found');

    res.json(result.recordset[0]);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Update a user
 *     description: Update user information. Requires authentication.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *               name:
 *                 type: string
 *               lastname:
 *                 type: string
 *     responses:
 *       200:
 *         description: User updated successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
// PUT update user (protected)
router.put('/:id', async (req, res) => {
  const { username, email, name, lastname } = req.body;

  try {
    await poolConnect;

    await pool.request()
      .input('id', sql.Int, req.params.id)
      .input('username', sql.NVarChar(50), username)
      .input('email', sql.NVarChar(255), email)
      .input('name', sql.NVarChar(100), name || null)
      .input('lastname', sql.NVarChar(100), lastname || null)
      .query(`UPDATE noriusers
              SET username = @username,
                  email = @email,
                  name = @name,
                  lastname = @lastname
              WHERE user_id = @id`);

    res.send('User updated');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete a user
 *     description: Delete a specific user by ID. Requires authentication.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
// DELETE user (protected)
router.delete('/:id', async (req, res) => {
  try {
    await poolConnect;
    await pool.request()
      .input('id', sql.Int, req.params.id)
      .query('DELETE FROM noriusers WHERE user_id = @id');
    res.send('User deleted');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

module.exports = router;
