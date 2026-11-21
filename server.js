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
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

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
  const {
    email,
    password,
    firstname,
    lastname,
    phone,
    city,
    state,
    country,
    message,
    jobtitle,
    company,
    field_of_study,
    asunto,
    hs_linkedin_url
  } = req.body;

  if (
    typeof email !== 'string' ||
    !email.trim() ||
    typeof password !== 'string' ||
    !password
  ) {
    return res.status(400).json({
      success: false,
      message: 'Email y contraseña requeridos.'
    });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();

    // 1. Buscar si el contacto existe.
    const searchRequest = {
      filterGroups: [
        {
          filters: [
            {
              propertyName: 'email',
              operator: 'EQ',
              value: cleanEmail
            }
          ]
        }
      ],
      properties: ['email', 'password_hash'],
      limit: 1
    };

    const searchApiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/contacts/search',
      body: searchRequest
    });

    const searchResponse = await searchApiResponse.json();
    const existingContact = searchResponse.results[0];

    if (existingContact?.properties?.password_hash) {
      return res.status(409).json({
        success: false,
        message: 'Este correo ya tiene acceso activado.'
      });
    }

    // 2. Generar el hash de la contraseña.
    const hashedPassword = await bcrypt.hash(password, 10);

    // Propiedades opcionales para creación y actualización.
    const optionalProperties = {
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
      ...(hs_linkedin_url && { hs_linkedin_url })
    };

    // 3. Actualizar el contacto existente.
    // PENDIENTE DE SEGURIDAD:
    // verificar la propiedad del correo antes de activar el acceso.
    if (existingContact) {
      await hubspotClient.apiRequest({
        method: 'PATCH',
        path:
          '/crm/objects/2026-03/contacts/' +
          encodeURIComponent(existingContact.id),
        body: {
          properties: {
            password_hash: hashedPassword,
            military_status: 'Activo',
            ...optionalProperties
          }
        }
      });

      return res.status(200).json({
        success: true,
        message: 'Acceso activado correctamente.'
      });
    }

    // 4. Crear un contacto nuevo.
    const properties = {
      email: cleanEmail,
      firstname: firstname || '',
      lastname: lastname || '',
      password_hash: hashedPassword,
      military_status: 'Activo',
      ...optionalProperties
    };

    const createApiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/contacts',
      body: {
        properties,
        associations: []
      }
    });

    const createdContact = await createApiResponse.json();

    return res.status(201).json({
      success: true,
      message: 'Usuario registrado con éxito.',
      id: createdContact.id
    });
  } catch (error) {
    // No registrar contraseñas, hashes ni el cuerpo completo del error.
    console.error('Error en registro de contacto en HubSpot:', {
      status: error.statusCode ?? error.code ?? 'UNKNOWN'
    });

    return res.status(500).json({
      success: false,
      message: 'No se pudo completar el registro. Intenta nuevamente.'
    });
  }
});


// --- API RECUPERACIÓN DE CONTRASEÑA - PASO 1: VERIFICAR IDENTIDAD Y GENERAR TOKEN ---
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({
      success: false,
      message: 'El correo electrónico es obligatorio.'
    });
  }

  const genericResponse = {
    success: true,
    message:
      'Si existe una cuenta asociada a este correo, recibirás instrucciones para restablecer tu contraseña.'
  };

  try {
    const cleanEmail = email.trim().toLowerCase();

    // 1. Buscar el contacto usando la API 2026-03.
    const searchRequest = {
      filterGroups: [
        {
          filters: [
            {
              propertyName: 'email',
              operator: 'EQ',
              value: cleanEmail
            }
          ]
        }
      ],
      properties: ['email', 'firstname'],
      limit: 1
    };

    const searchApiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/contacts/search',
      body: searchRequest
    });

    const searchResponse = await searchApiResponse.json();
    const contact = searchResponse.results[0];

    // No revelar si el correo existe.
    if (!contact) {
      return res.status(200).json(genericResponse);
    }

    // 2. Generar un token válido por 15 minutos.
    // contactId se guarda como texto para ser compatible
    // con el endpoint reset-password anterior.
    const resetToken = jwt.sign(
      {
        contactId: String(contact.id),
        email: cleanEmail,
        purpose: 'password_reset'
      },
      JWT_SECRET,
      {
        expiresIn: '15m'
      }
    );

    // 3. Construir el enlace desde una URL configurada en el servidor.
    if (!process.env.FRONTEND_URL) {
      throw new Error('FRONTEND_URL no está configurada.');
    }

    const resetUrl = new URL(
      '/restablecer-password.html',
      process.env.FRONTEND_URL
    );

    if (resetUrl.protocol !== 'https:') {
      throw new Error('FRONTEND_URL debe utilizar HTTPS.');
    }

    resetUrl.searchParams.set('token', resetToken);

    // Escapar valores que se insertan en el HTML.
    const escapeHtml = (value) =>
      String(value).replace(/[&<>"']/g, (character) => {
        const entities = {
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;'
        };

        return entities[character];
      });

    const nombre = escapeHtml(
      contact.properties?.firstname || 'Ejecutivo'
    );

    const resetLink = escapeHtml(resetUrl.toString());

    // 4. Enviar el correo y comprobar el error devuelto por Resend.
    const { data, error: sendError } = await resend.emails.send({
      from: 'Boardroom Business School <soporte@boardroom-business.school>',
      to: cleanEmail,
      subject: 'Restablece tu contraseña - Boardroom Business School',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
          <h2>Hola, ${nombre}</h2>

          <p>
            Recibimos una solicitud para restablecer la contraseña
            de tu cuenta en Boardroom Business School.
          </p>

          <p>
            Haz clic en el siguiente botón para crear una nueva
            contraseña. Este enlace expira en 15 minutos.
          </p>

          <a
            href="${resetLink}"
            style="display: inline-block; padding: 12px 24px; background-color: #000; color: #fff; text-decoration: none; border-radius: 5px; margin: 16px 0;"
          >
            Restablecer contraseña
          </a>

          <p style="font-size: 12px; color: #666;">
            Si no solicitaste este cambio, puedes ignorar este correo.
          </p>
        </div>
      `
    });

    if (sendError || !data?.id) {
      // No registrar el enlace, el token ni información del destinatario.
      console.error('Fallo en el envío del correo de recuperación.');

      // Mantener la misma respuesta pública para no revelar
      // la existencia de la cuenta.
      return res.status(200).json(genericResponse);
    }

    // Nunca devolver el token de recuperación en el JSON.
    return res.status(200).json(genericResponse);
  } catch (error) {
    console.error('Error en forgot-password:', {
      status: error.statusCode ?? error.code ?? 'UNKNOWN'
    });

    return res.status(500).json({
      success: false,
      message: 'No se pudo procesar la solicitud de recuperación.'
    });
  }
});



// --- API RECUPERACIÓN DE CONTRASEÑA - PASO 2: ESTABLECER NUEVA CONTRASEÑA ---
app.post('/api/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body;

  if (
    typeof resetToken !== 'string' ||
    !resetToken.trim() ||
    typeof newPassword !== 'string' ||
    !newPassword
  ) {
    return res.status(400).json({
      success: false,
      message: 'El token de recuperación y la nueva contraseña son requeridos.'
    });
  }

  try {
    // 1. Verificar la firma y la vigencia del token.
    const decoded = jwt.verify(resetToken.trim(), JWT_SECRET);

    if (
      !decoded ||
      typeof decoded !== 'object' ||
      decoded.purpose !== 'password_reset'
    ) {
      return res.status(403).json({
        success: false,
        message: 'Token inválido para esta operación.'
      });
    }

    // Exigir un identificador válido y una fecha de expiración.
    if (
      typeof decoded.contactId !== 'string' ||
      !decoded.contactId.trim() ||
      typeof decoded.exp !== 'number'
    ) {
      return res.status(403).json({
        success: false,
        message: 'Token de recuperación incompleto o inválido.'
      });
    }

    // 2. Generar el hash de la nueva contraseña.
    // No aplicar trim() a la contraseña.
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // 3. Actualizar el contacto usando la API 2026-03.
    await hubspotClient.apiRequest({
      method: 'PATCH',
      path:
        '/crm/objects/2026-03/contacts/' +
        encodeURIComponent(decoded.contactId.trim()),
      body: {
        properties: {
          password_hash: hashedNewPassword
        }
      }
    });

    return res.status(200).json({
      success: true,
      message:
        'Tu contraseña ha sido restablecida con éxito. Ya puedes iniciar sesión.'
    });
  } catch (error) {
    if (
      error.name === 'TokenExpiredError' ||
      error.name === 'JsonWebTokenError' ||
      error.name === 'NotBeforeError'
    ) {
      return res.status(401).json({
        success: false,
        message:
          'El enlace o token de recuperación ha expirado o es inválido.'
      });
    }

    // No registrar tokens, contraseñas, hashes ni el cuerpo completo del error.
    console.error('Error en reset-password:', {
      status: error.statusCode ?? error.code ?? 'UNKNOWN'
    });

    return res.status(500).json({
      success: false,
      message: 'Error interno al actualizar la contraseña en HubSpot.'
    });
  }
});




// --- API LOGIN ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (
    typeof email !== 'string' ||
    !email.trim() ||
    typeof password !== 'string' ||
    !password
  ) {
    return res.status(400).json({
      success: false,
      message: 'Email y contraseña requeridos.'
    });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();

    // Solicitar explícitamente los campos utilizados en el login.
    const loginProperties = [
      'email',
      'password_hash',
      'firstname',
      'lastname',
      'phone',
      'jobtitle',
      'company',
      'empresa',
      'field_of_study',
      'military_status',
      'matricula_escolar',
      'city',
      'state',
      'country',
      'message',
      'asunto',
      'hs_linkedin_url'
    ];

    const searchRequest = {
      filterGroups: [
        {
          filters: [
            {
              propertyName: 'email',
              operator: 'EQ',
              value: cleanEmail
            }
          ]
        }
      ],
      properties: loginProperties,
      limit: 1
    };

    // Buscar el contacto usando la API 2026-03.
    const searchApiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/contacts/search',
      body: searchRequest
    });

    const searchResponse = await searchApiResponse.json();

    const contact = searchResponse.results[0];
    const savedPasswordHash = contact?.properties?.password_hash;

    if (!contact || !savedPasswordHash) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales incorrectas.'
      });
    }

    const match = await bcrypt.compare(password, savedPasswordHash);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales incorrectas.'
      });
    }

    // Lista explícita: no incluir password_hash en la respuesta ni en el JWT.
    const userData = {
      id: contact.id,
      email: contact.properties.email,
      firstname: contact.properties.firstname || '',
      lastname: contact.properties.lastname || '',
      phone: contact.properties.phone || '',
      jobtitle: contact.properties.jobtitle || '',
      company: contact.properties.company || '',
      empresa: contact.properties.empresa || '',
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

    const token = jwt.sign(userData, JWT_SECRET, {
      expiresIn: '8h'
    });

    return res.status(200).json({
      success: true,
      message: `¡Bienvenido, ${userData.firstname || 'Ejecutivo'}!`,
      token,
      user: userData
    });
  } catch (error) {
    // No registrar contraseñas, hashes ni el cuerpo completo del error.
    console.error('Error en login:', {
      status: error.statusCode ?? error.code ?? 'UNKNOWN'
    });

    return res.status(500).json({
      success: false,
      message: 'Error en la verificación de credenciales.'
    });
  }
});

// --- API PERFIL (AUTENTICADO) ---
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Token no provisto.'
    });
  }

  const token = authHeader.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token no provisto.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    return res.status(200).json({
      success: true,
      user: decoded
    });
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: 'Sesión expirada o inválida.'
    });
  }
});

// --- API REGISTRO IN-HOUSE ---
app.post('/api/reginhouse', async (req, res) => {
  const {
    email,
    password,
    firstname,
    lastname,
    phone,
    city,
    state,
    country,
    message,
    jobtitle,
    company,
    field_of_study,
    asunto,
    hs_linkedin_url
  } = req.body;

  if (
    typeof email !== 'string' ||
    !email.trim() ||
    typeof password !== 'string' ||
    !password
  ) {
    return res.status(400).json({
      success: false,
      message: 'Email y contraseña requeridos.'
    });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();

    // 1. Buscar si el contacto existe.
    // Se solicita password_hash explícitamente para comprobar
    // si el contacto ya tiene acceso activado.
    const searchRequest = {
      filterGroups: [
        {
          filters: [
            {
              propertyName: 'email',
              operator: 'EQ',
              value: cleanEmail
            }
          ]
        }
      ],
      properties: ['email', 'password_hash'],
      limit: 1
    };

    const searchApiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/contacts/search',
      body: searchRequest
    });

    const searchResponse = await searchApiResponse.json();

    const existingContact = searchResponse.results[0];

    if (existingContact?.properties?.password_hash) {
      return res.status(409).json({
        success: false,
        message: 'Este correo ya tiene acceso activado.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Propiedades opcionales compartidas por creación y actualización.
    const optionalProperties = {
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
      ...(hs_linkedin_url && { hs_linkedin_url })
    };

    // 2. Actualizar el contacto existente.
    // IMPORTANTE: antes de activar el acceso, debes verificar
    // que la persona controla el correo mediante un enlace
    // o código de verificación de un solo uso.
    if (existingContact) {
      await hubspotClient.apiRequest({
        method: 'PATCH',
        path:
          '/crm/objects/2026-03/contacts/' +
          encodeURIComponent(existingContact.id),
        body: {
          properties: {
            password_hash: hashedPassword,
            military_status: 'Activo',
            ...optionalProperties
          }
        }
      });

      return res.status(200).json({
        success: true,
        message: 'Acceso activado correctamente.'
      });
    }

    // 3. Crear un nuevo contacto.
    const properties = {
      email: cleanEmail,
      firstname: firstname || '',
      lastname: lastname || '',
      password_hash: hashedPassword,
      military_status: 'Activo',
      ...optionalProperties
    };

    const createApiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/contacts',
      body: {
        properties,
        associations: []
      }
    });

    const createdContact = await createApiResponse.json();

    return res.status(201).json({
      success: true,
      message: 'Usuario registrado con éxito.',
      id: createdContact.id
    });
  } catch (error) {
    // Evita registrar el cuerpo completo de la solicitud
    // o del error: podría contener información sensible.
    console.error('Error en registro de contacto en HubSpot:', {
      status: error.statusCode ?? error.code ?? 'UNKNOWN'
    });

    return res.status(500).json({
      success: false,
      message: 'No se pudo completar el registro. Intenta nuevamente.'
    });
  }
});

// --- EMPRESAS: Crear o Vincular una Empresa ---
app.post('/api/companies', async (req, res) => {
  const { name, domain } = req.body;

  try {
    const apiResponse = await hubspotClient.apiRequest({
      method: 'POST',
      path: '/crm/objects/2026-03/companies',
      body: {
        properties: { name, domain },
        associations: []
      }
    });

    const company = await apiResponse.json();

    return res.status(201).json({
      success: true,
      company
    });
  } catch (error) {
    console.error('Error creando empresa:', error.body || error);

    return res.status(500).json({
      success: false,
      message: 'Error creando empresa en HubSpot.'
    });
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
    await hubspotClient.apiRequest({
      method: 'PUT',
      path:
        `/crm/objects/2026-03/deal/${encodeURIComponent(dealResponse.id)}` +
        `/associations/default/contact/${encodeURIComponent(contactId)}`
    });
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
    await hubspotClient.apiRequest({
      method: 'PUT',
      path:
        `/crm/objects/2026-03/ticket/${encodeURIComponent(ticketResponse.id)}` +
        `/associations/default/contact/${encodeURIComponent(contactId)}`
      });
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


// REGLA DE ORO DE RENDER: Las rutas estáticas SIEMPRE van al final para evitar el error 405
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend API escuchando en puerto ${PORT}`));