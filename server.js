require('dotenv').config();
const express = require('express');
const cors = require('cors');
const hubspot = require('@hubspot/api-client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

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
    'phone', 'jobtitle', 'company', 'field_of_study', 'hs_registration_method', 'matricula_escolar'
];

// Endpoint de prueba / healthcheck
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'API de Boardroom Business School activa' });
});

// --- API REGISTRO ---
app.post('/api/register', async (req, res) => {
  const { email, password, firstname, lastname } = req.body;

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
          userstatus: 'Activo',
          ...(firstname && { firstname }),
          ...(lastname && { lastname })
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
      userstatus: 'Activo'
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
            hs_registration_method: contact.properties.hs_registration_method || 'Activo',
            matricula_escolar: contact.properties.matricula_escolar || ''
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

// --- MPRESAS: Crear o Vincular una Empresa ---
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend API escuchando en puerto ${PORT}`));