require('dotenv').config();
const express = require('express');
const cors = require('cors');
const hubspot = require('@hubspot/api-client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const DATA_FILE = path.join(__dirname, 'blogs.json');
const { Pool } = require('pg');

const app = express();

const DBUser = process.env.DBUser || 'boardroom_secret_key_2026';
const DBHost = process.env.DBHost || 'boardroom_secret_key_2026';
const DBB = process.env.DBB || 'boardroom_secret_key_2026';
const DBPass = process.env.DBPass || 'boardroom_secret_key_2026';
const DBPort = process.env.DBPort || 'boardroom_secret_key_2026';

const pool = new Pool({
  user: DBUser,
  host: DBHost,
  database: DBB,
  password: DBPass,
  port: DBPort,
});

// Habilitar CORS para permitir peticiones desde la web estática
app.use(cors({
    origin: '*', // En producción puedes poner el dominio de tu frontend estático (ej: https://tu-sitio-estatico.onrender.com)
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'boardroom_secret_key_2026';
const hubspotClient = new hubspot.Client({ accessToken: process.env.HUBSPOT_ACCESS_TOKEN || process.env.HUBSPOT_TOKEN });

const CONTACT_PROPERTIES = [
    'email', 'firstname', 'lastname', 'password_hash',
  'phone', 'jobtitle', 'company', 'field_of_study', 'military_status', 'matricula_escolar', 'city', 'state',
  'country', 'message', 'asunto', 'hs_linkedin_url','mobilephone'
];

// Endpoint de prueba / healthcheck
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'API de Boardroom Business School activa' });
});

// INICIO DE LA API DE USUARIOS DE LA PAGINA WEB

// --- API REGISTRO ---
app.post('/api/register', async (req, res) => {
  const { email, password, firstname, lastname, phone, city, state, country, message, jobtitle, company, field_of_study,asunto,hs_linkedin_url } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email y contraseña requeridos.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const cleanEmail = email.trim().toLowerCase();

    // 1. Buscar si el contacto existe
    const searchRequest = {
      filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: cleanEmail }] }],
      properties: CONTACT_PROPERTIES,
      limit: 1
    };

    const searchResponse = await hubspotClient.crm.contacts.searchApi.doSearch(searchRequest);

    if (searchResponse.results.length > 0) {
      const existingContact = searchResponse.results[0];

      if (existingContact.properties.password_hash) {
        return res.status(409).json({ success: false, message: 'Este correo ya tiene acceso activado.' });
      }

      await hubspotClient.crm.contacts.basicApi.update(existingContact.id, {
        properties: {
          password_hash: hashedPassword,
          military_status: 'Activo',
          ...(firstname && { firstname }),
          ...(lastname && { lastname }),
          ...(phone && { phone }),
          ...(city && { city }),
          ...(state && { state }),
          ...(country && { country }),
          ...(message && { message }),
          ...(asunto && { asunto }),
          ...(jobtitle && { jobtitle }),
          ...(company && { company }),
          ...(field_of_study && { field_of_study }),
          ...(asunto && { asunto }),
          ...(hs_linkedin_url && { hs_linkedin_url })
        }
      });

      return res.status(200).json({ success: true, message: 'Acceso activado correctamente.' });
    }

    // 2. Crear un nuevo contacto
    const properties = {
      email: cleanEmail,
      firstname: firstname || '',
      lastname: lastname || '',
      password_hash: hashedPassword,
      military_status: 'Activo',
      ...(phone && { phone }),
      ...(city && { city }),
      ...(state && { state }),
      ...(country && { country }),
      ...(message && { message }),
      ...(asunto && { asunto }),
      ...(jobtitle && { jobtitle }),
      ...(company && { company }),
      ...(field_of_study && { field_of_study }),
      ...(asunto && { asunto }),
      ...(hs_linkedin_url && { hs_linkedin_url })
    };

    const apiResponse = await hubspotClient.crm.contacts.basicApi.create({ properties });

    return res.status(201).json({
      success: true,
      message: 'Usuario registrado con éxito.',
      id: apiResponse.id
    });

  } catch (error) {
    // ESTA LÍNEA MOSTRARÁ EL ERROR REAL EN RENDER
    const hubspotError = error.body?.message || error.message || error;
    console.error('CRÍTICO - Error HubSpot CRM:', JSON.stringify(error.body || error, null, 2));

    return res.status(500).json({
      success: false,
      message: `Error en HubSpot: ${hubspotError}`
    });
  }
});


// --- API CAMBIAR CONTRASEÑA (PARA RENDER.COM) ---
app.post('/api/change-password', async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  // 1. Validación estricta de campos obligatorios
  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ 
      success: false, 
      message: 'El correo, la contraseña actual y la nueva contraseña son requeridos.' 
    });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();

    // 2. Buscar al contacto en HubSpot usando tu cliente oficial
    const searchRequest = {
      filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: cleanEmail }] }],
      properties: ['email', 'password_hash'], // Traemos explícitamente el hash actual
      limit: 1
    };

    const searchResponse = await hubspotClient.crm.contacts.searchApi.doSearch(searchRequest);

    // Si el usuario no existe en el CRM
    if (!searchResponse.results || searchResponse.results.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'El usuario no existe en la base de datos de Boardroom.' 
      });
    }

    const contact = searchResponse.results[0];
    const currentHash = contact.properties.password_hash;

    // Si el contacto existe pero nunca ha activado una contraseña
    if (!currentHash) {
      return res.status(400).json({ 
        success: false, 
        message: 'Este usuario no tiene un acceso activo en el portal. Regístrese primero.' 
      });
    }

    // 3. Validar con bcrypt si la contraseña actual coincide
    const isPasswordValid = await bcrypt.compare(currentPassword, currentHash);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'La contraseña actual introducida es incorrecta.' 
      });
    }

    // 4. Hashear la nueva contraseña con el algoritmo clásico
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // 5. Actualizar la propiedad en HubSpot usando el ID numérico del contacto
    await hubspotClient.crm.contacts.basicApi.update(contact.id, {
      properties: {
        password_hash: hashedNewPassword
      }
    });

    // RESPUESTA GARANTIZADA: Enviamos un JSON válido al frontend
    return res.status(200).json({ 
      success: true, 
      message: 'Contraseña actualizada con éxito en la plataforma.' 
    });

  } catch (error) {
    // Captura de errores avanzada para los logs de Render
    const hubspotError = error.body?.message || error.message || error;
    console.error('CRÍTICO - Error en Servidor Render (Change Password):', JSON.stringify(error.body || error, null, 2));

    // Forzamos el envío de un JSON estructurado incluso si cae en el catch
    return res.status(500).json({
      success: false,
      message: `Error interno en el servidor: ${hubspotError}`
    });
  }
});


// --- API LOGIN ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email y contraseña requeridos.' });
    }

    try {
        const cleanEmail = email.trim().toLowerCase();
        const searchRequest = {
            filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: cleanEmail }] }],
            properties: CONTACT_PROPERTIES,
            limit: 1
        };

        const searchResponse = await hubspotClient.crm.contacts.searchApi.doSearch(searchRequest);

        if (searchResponse.results.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales incorrectas o usuario no encontrado.' });
        }

        const contact = searchResponse.results[0];
        const savedPasswordHash = contact.properties.password_hash;

        if (!savedPasswordHash) {
            return res.status(401).json({ success: false, message: 'El usuario no tiene una contraseña configurada.' });
        }

        const match = await bcrypt.compare(password, savedPasswordHash);

        if (!match) {
            return res.status(401).json({ success: false, message: 'Credenciales incorrectas.' });
        }

        const userData = {
            id: contact.id,
            email: contact.properties.email,
            firstname: contact.properties.firstname || '',
            lastname: contact.properties.lastname || '',
            phone: contact.properties.phone || '',
            jobtitle: contact.properties.jobtitle || '',
            company: contact.properties.company || '',
            field_of_study: contact.properties.field_of_study || '',
            military_status: contact.properties.military_status || 'Activo',
            matricula_escolar: contact.properties.matricula_escolar || '',
            city: contact.properties.city || '',
            state: contact.properties.state || '',
            country: contact.properties.country || '',
            message: contact.properties.message || '',
            asunto: contact.properties.asunto || '',
            hs_linkedin_url: contact.properties.hs_linkedin_url || ''
        };
      
      
      const token = jwt.sign(userData, JWT_SECRET, { expiresIn: '8h' });

        return res.status(200).json({
            success: true,
            message: `¡Bienvenido, ${userData.firstname || 'Ejecutivo'}!`,
            token: token,
            user: userData
        });

    } catch (error) {
        console.error('Error en login:', error.body || error);
        return res.status(500).json({ success: false, message: 'Error en la verificación de credenciales.' });
    }
});

// --- API PERFIL (AUTENTICADO) ---
app.get('/api/profile', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Token no provisto.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return res.status(200).json({ success: true, user: decoded });
    } catch (err) {
        return res.status(401).json({ success: false, message: 'Sesión expirada o inválida.' });
    }
});

// --- API REGISTRO IN-HOUSE ---
app.post('/api/reginhouse', async (req, res) => {
  const { email, password, firstname, lastname, phone, city, state, country, message, jobtitle, company, field_of_study,asunto,hs_linkedin_url } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email y contraseña requeridos.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const cleanEmail = email.trim().toLowerCase();

    // 1. Buscar si el contacto existe
    const searchRequest = {
      filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: cleanEmail }] }],
      properties: CONTACT_PROPERTIES,
      limit: 1
    };

    const searchResponse = await hubspotClient.crm.contacts.searchApi.doSearch(searchRequest);

    if (searchResponse.results.length > 0) {
      const existingContact = searchResponse.results[0];

      if (existingContact.properties.password_hash) {
        return res.status(409).json({ success: false, message: 'Este correo ya tiene acceso activado.' });
      }

      await hubspotClient.crm.contacts.basicApi.update(existingContact.id, {
        properties: {
          password_hash: hashedPassword,
          military_status: 'Activo',
          ...(firstname && { firstname }),
          ...(lastname && { lastname }),
          ...(phone && { phone }),
          ...(city && { city }),
          ...(state && { state }),
          ...(country && { country }),
          ...(message && { message }),
          ...(asunto && { asunto }),
          ...(jobtitle && { jobtitle }),
          ...(company && { company }),
          ...(field_of_study && { field_of_study }),
          ...(asunto && { asunto }),
          ...(hs_linkedin_url && { hs_linkedin_url })
        }
      });

      return res.status(200).json({ success: true, message: 'Acceso activado correctamente.' });
    }

    // 2. Crear un nuevo contacto
    const properties = {
      email: cleanEmail,
      firstname: firstname || '',
      lastname: lastname || '',
      password_hash: hashedPassword,
      military_status: 'Activo',
      ...(phone && { phone }),
      ...(city && { city }),
      ...(state && { state }),
      ...(country && { country }),
      ...(message && { message }),
      ...(asunto && { asunto }),
      ...(jobtitle && { jobtitle }),
      ...(company && { company }),
      ...(field_of_study && { field_of_study }),
      ...(asunto && { asunto }),
      ...(hs_linkedin_url && { hs_linkedin_url })
    };

    const apiResponse = await hubspotClient.crm.contacts.basicApi.create({ properties });

    return res.status(201).json({
      success: true,
      message: 'Usuario registrado con éxito.',
      id: apiResponse.id
    });

  } catch (error) {
    // ESTA LÍNEA MOSTRARÁ EL ERROR REAL EN RENDER
    const hubspotError = error.body?.message || error.message || error;
    console.error('CRÍTICO - Error HubSpot CRM:', JSON.stringify(error.body || error, null, 2));

    return res.status(500).json({
      success: false,
      message: `Error en HubSpot: ${hubspotError}`
    });
  }
});

// --- EMPRESAS: Crear o Vincular una Empresa ---
app.post('/api/companies', async (req, res) => {
  const { name, domain } = req.body;

  try {
    const response = await hubspotClient.crm.companies.basicApi.create({
      properties: { name, domain }
    });
    return res.status(201).json({ success: true, company: response });
  } catch (error) {
    console.error('Error creando empresa:', error.body || error);
    return res.status(500).json({ success: false, message: 'Error creando empresa en HubSpot.' });
  }
});

// --- NEGOCIOS (DEALS): Registrar Oportunidades o Inscripciones ---
app.post('/api/deals', async (req, res) => {
  const { dealname, amount, pipeline, dealstage, contactId } = req.body;

  try {
    // Crear el negocio
    const dealResponse = await hubspotClient.crm.deals.basicApi.create({
      properties: {
        dealname: dealname,
        amount: amount || '0',
        pipeline: pipeline || 'default',
        dealstage: dealstage || 'appointmentscheduled'
      }
    });

    // Asociar el negocio con el Contacto si se provee contactId
    if (contactId) {
      await hubspotClient.crm.associations.v4.basicApi.createDefault(
        'deal',
        dealResponse.id,
        'contact',
        contactId
      );
    }

    return res.status(201).json({ success: true, deal: dealResponse });
  } catch (error) {
    console.error('Error creando negocio:', error.body || error);
    return res.status(500).json({ success: false, message: 'Error creando oportunidad en HubSpot.' });
  }
});

// --- TICKETS: Sistema de Soporte o Consultas Alumnos ---
app.post('/api/tickets', async (req, res) => {
  const { subject, content, hs_ticket_priority, contactId } = req.body;

  try {
    const ticketResponse = await hubspotClient.crm.tickets.basicApi.create({
      properties: {
        hs_pipeline: '0',
        hs_pipeline_stage: '1',
        subject: subject,
        content: content,
        hs_ticket_priority: hs_ticket_priority || 'HIGH'
      }
    });

    if (contactId) {
      await hubspotClient.crm.associations.v4.basicApi.createDefault(
        'ticket',
        ticketResponse.id,
        'contact',
        contactId
      );
    }

    return res.status(201).json({ success: true, ticket: ticketResponse });
  } catch (error) {
    console.error('Error creando ticket:', error.body || error);
    return res.status(500).json({ success: false, message: 'Error creando ticket en HubSpot.' });
  }
});

// --- WEBHOOKS: Recibir actualizaciones desde HubSpot ---
app.post('/api/webhooks/hubspot', (req, res) => {
  const events = req.body; // HubSpot envía un array de eventos

  events.forEach(event => {
    console.log(`Evento de HubSpot recibido [${event.subscriptionType}]:`, event);
    // Ejemplo: Si un alumno cambió de programa o estatus en HubSpot CRM, 
    // puedes actualizar tu base de datos local o invalidar sesiones cacheadas.
  });

  // Responder 200 OK inmediatamente para confirmar recepción a HubSpot
  res.status(200).send('EVENT_RECEIVED');
});

// TERMINO DE LA API DE USUARIOS DE LA PAGINA WEB


  //-------------------------------------------------------------------------------------------------------


// INICIO DE LA API DE LOS EVENTOS PAGINA DE INICIO

// LEER EVENTOS PAGINA DE INICIO
app.get('/api/eventos', (req, res) => {
  const rutaArchivo = path.join(__dirname, 'eventos.json');
  
  fs.readFile(rutaArchivo, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'No se pudo leer la base de datos de eventos.' });
    }
    res.json(JSON.parse(data));
  });
});

// TERMINO DE LA API DE LOS EVENTOS PAGINA DE INICIO



//-------------------------------------------------------------------------------------------------------



// INICIO DE LA API DE LOS CURSOS CORTOS
// LEER CURSOS
app.get('/api/cursos', (req, res) => {
  const rutaArchivo = path.join(__dirname, 'cursos.json');
  
  fs.readFile(rutaArchivo, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'No se pudo leer la base de datos de cursos.' });
    }
    res.json(JSON.parse(data));
  });
});

// NUEVO - API: Obtener un solo curso por su ID
app.get('/api/cursos/:id', (req, res) => {
  const cursoId = parseInt(req.params.id);

  fs.readFile(CURSOS_FILE, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Error al leer los datos de los cursos.' });
    }

    const cursos = JSON.parse(data);
    const cursoEncontrado = cursos.find(c => c.id === cursoId);

    if (!cursoEncontrado) {
      return res.status(404).json({ error: 'El curso solicitado no existe.' });
    }

    res.json(cursoEncontrado);
  });
});

// app.get('/api/cursos', async (req, res) => {
//   try {
//     // Realizamos la consulta a la tabla 'diplomados'
//     const resultado = await pool.query('SELECT * FROM diplomados ORDER BY fecha ASC');
    
//     // Devolvemos las filas obtenidas en formato JSON
//     res.json(resultado.rows);
//   } catch (err) {
//     console.error('Error al consultar la base de datos:', err);
//     res.status(500).json({ error: 'No se pudo leer la base de datos de cursos.' });
//   }
// });

// TERMINO DE LA API DE LOS CURSOS CORTOS


//-------------------------------------------------------------------------------------------------------


// INICIO DE LA API DE LOS NEWSLETTERS (BLOGS) DE BOARDROOM

// Función auxiliar para generar un slug amigable a partir del título (ej: "Hola Mundo" -> "hola-mundo")
const generarSlug = (texto) => {
  return texto
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')       // Reemplaza espacios con guiones
    .replace(/[^\w\-]+/g, '')   // Remueve caracteres no válidos
    .replace(/\-\-+/g, '-');    // Elimina guiones duplicados
};

// =======================================================
// API DE NEWSLETTERS PARA BOARDROOM (MIGRADO A POSTGRESQL)
// =======================================================

// Endpoint para obtener todos los newsletters publicados (GET)
app.get('/api/newsletters', async (req, res) => {
  try {
    const queryText = 'SELECT id, slug, titulo, subtitulo, imagen_destacada_url, autor_nombre, es_exclusivo, status, published_at FROM newsletters WHERE status = $1 ORDER BY published_at DESC';
    const { rows } = await pool.query(queryText, ['publicado']);
    
    res.json(rows);
  } catch (err) {
    console.error('Error al leer de PostgreSQL:', err);
    res.status(500).json({ error: 'Error interno al leer los datos del servidor' });
  }
});

// Endpoint para buscar newsletters por palabra clave en título o contenido (GET)
app.get('/api/newsletters/search', async (req, res) => {
  const query = req.query.q;

  if (!query) {
    return res.status(400).json({ error: 'Debes proporcionar un término de búsqueda en el parámetro ?q=' });
  }

  try {
    // Usamos ILIKE de PostgreSQL para búsquedas insensibles a mayúsculas/minúsculas y acentos
    const sqlMatch = `%${query}%`;
    const queryText = `
      SELECT id, slug, titulo, subtitulo, status, published_at 
      FROM newsletters 
      WHERE (titulo ILIKE $1 OR contenido_html ILIKE $1 OR contenido_texto ILIKE $1)
      AND status = 'publicado'
    `;
    
    const { rows } = await pool.query(queryText, [sqlMatch]);

    res.json({
      busqueda: query,
      totalResultados: rows.length,
      resultados: rows
    });
  } catch (err) {
    console.error('Error en la búsqueda de PostgreSQL:', err);
    res.status(500).json({ error: 'Error interno al realizar la búsqueda' });
  }
});

// Endpoint para obtener un solo newsletter por su SLUG (Ideal para las URLs de Boardroom)
app.get('/api/newsletters/:slug', async (req, res) => {
  const blogSlug = req.params.slug;
  
  try {
    const queryText = 'SELECT * FROM newsletters WHERE slug = $1';
    const { rows } = await pool.query(queryText, [blogSlug]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Newsletter no encontrado' });
    }
    
    // Opcional: Incrementar el contador de vistas web de manera asíncrona
    pool.query('UPDATE newsletters SET total_vistas_web = total_vistas_web + 1 WHERE slug = $1', [blogSlug]).catch(err => console.error(err));

    res.json(rows[0]);
  } catch (err) {
    console.error('Error al obtener el newsletter de PostgreSQL:', err);
    res.status(500).json({ error: 'Error interno al buscar la publicación' });
  }
});

// Endpoint para crear y publicar un nuevo newsletter (POST)
app.post('/api/newsletters', async (req, res) => {
  const { titulo, subtitulo, contenido_html, contenido_texto, imagen_destacada_url, autor_nombre, es_exclusivo } = req.body;

  // Validaciones mínimas obligatorias para la consistencia de datos
  if (!titulo || !contenido_html || !contenido_texto) {
    return res.status(400).json({ error: 'El título, contenido_html y contenido_texto son obligatorios.' });
  }

  try {
    const slug = generarSlug(titulo);
    const status = 'publicado'; // Se guarda directamente como publicado
    const published_at = new Date();

    const queryText = `
      INSERT INTO newsletters 
      (slug, titulo, subtitulo, contenido_html, contenido_texto, imagen_destacada_url, autor_nombre, es_exclusivo, status, published_at) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
      RETURNING *
    `;
    
    const values = [
      slug, 
      titulo, 
      subtitulo || null, 
      contenido_html, 
      contenido_texto, 
      imagen_destacada_url || null, 
      autor_nombre || 'Equipo Boardroom', 
      es_exclusivo || false, 
      status, 
      published_at
    ];

    const { rows } = await pool.query(queryText, values);

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Error al guardar en PostgreSQL:', err);
    // Controlar errores de duplicidad en el SLUG (Llave única)
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Ya existe una publicación con un título idéntico o muy similar.' });
    }
    res.status(500).json({ error: 'Error interno al intentar guardar la publicación.' });
  }
});

// TERMINO DE LA API DE LOS NEWSLETTERS

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend API escuchando en puerto ${PORT}`));