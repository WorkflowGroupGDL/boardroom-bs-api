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
    'phone', 'jobtitle', 'company', 'program', 'userstatus', 'matricula_escolar'
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

        const searchRequest = {
            filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: cleanEmail }] }],
            properties: CONTACT_PROPERTIES,
            limit: 1
        };

        const searchResponse = await hubspotClient.crm.contacts.searchApi.doSearch(searchRequest);

        if (searchResponse.results.length > 0) {
            const existingContact = searchResponse.results[0];

            if (existingContact.properties.password_hash) {
                return res.status(409).json({ success: false, message: 'Este correo electrónico ya cuenta con una contraseña activada.' });
            }

            const updateProperties = {
                password_hash: hashedPassword,
                userstatus: 'Activo'
            };
            if (firstname) updateProperties.firstname = firstname;
            if (lastname) updateProperties.lastname = lastname;

            await hubspotClient.crm.contacts.basicApi.update(existingContact.id, { properties: updateProperties });

            return res.status(200).json({
                success: true,
                message: 'Acceso activado con éxito. Ya puedes iniciar sesión.'
            });
        }

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
            message: 'Usuario registrado con éxito en el sistema.',
            id: apiResponse.id
        });

    } catch (error) {
        console.error('Error en registro:', error.body || error);
        return res.status(500).json({ success: false, message: 'Error procesando la solicitud en HubSpot.' });
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
            program: contact.properties.program || '',
            userstatus: contact.properties.userstatus || 'Activo',
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend API escuchando en puerto ${PORT}`));