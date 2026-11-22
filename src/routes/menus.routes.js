const { Router } = require('express');
const fs = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'boardroom_secret_key_2026';
const MENUS_FILE = path.join(__dirname, '../config/menus.json');

const verificarToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Token no provisto.'
    });
  }

  const token = authHeader.slice(7).trim();

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: 'Sesión expirada o inválida.'
    });
  }
};

// GET /api/menus/mi-menu
router.get('/mi-menu', verificarToken, async (req, res) => {
  try {
    const rolUsuario = req.user.user_role || 'Cliente';

    const rawData = await fs.readFile(MENUS_FILE, 'utf8');
    const catalogoMenus = JSON.parse(rawData);

    const claveRol = Object.keys(catalogoMenus).find(
      (key) => key.toLowerCase() === String(rolUsuario).trim().toLowerCase()
    );

    if (!claveRol) {
      return res.status(404).json({
        success: false,
        message: `No hay menú configurado para el rol: ${rolUsuario}`
      });
    }

    return res.status(200).json({
      success: true,
      rol: claveRol,
      items: catalogoMenus[claveRol]
    });
  } catch (error) {
    console.error('Error al cargar menú dinámico:', error);
    return res.status(500).json({
      success: false,
      message: 'Error interno al obtener el menú.'
    });
  }
});

module.exports = router;
