const express = require("express");
require("dotenv").config();
const cors = require("cors");
const usuariosRouter = require("./routes/users");
const authRouter = require("./routes/auth");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("./swagger");

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for all routes

/**
 * @swagger
 * /api-docs:
 *   get:
 *     summary: Displays API documentation
 */
// Setup Swagger
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// API Routes
app.use("/api/users", usuariosRouter);
app.use("/api/auth", authRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} http://localhost:${PORT}`);
  console.log(`API Documentation available at http://localhost:${PORT}/api-docs`);
});




