/**
 * ==============================================================================
 * SANTANDER REAL ESTATE - CORE AUTHENTICATION & RBAC SECURITY MODULE
 * Enterprise Client-Side Architecture with NIST-Standard PBKDF2 Cryptography,
 * Route Guards, Anti-Brute Force Lockout & Inactivity Session Monitors.
 * ==============================================================================
 */

(function (global) {
  'use strict';

  // Detect environment
  const isBrowser = typeof window !== 'undefined';
  const storage = {
    local: {
      getItem(k) {
        if (isBrowser) return window.localStorage.getItem(k);
        return global.__mockLocal ? global.__mockLocal[k] : null;
      },
      setItem(k, v) {
        if (isBrowser) window.localStorage.setItem(k, v);
        else {
          global.__mockLocal = global.__mockLocal || {};
          global.__mockLocal[k] = String(v);
        }
      },
      removeItem(k) {
        if (isBrowser) window.localStorage.removeItem(k);
        else if (global.__mockLocal) delete global.__mockLocal[k];
      }
    },
    session: {
      getItem(k) {
        if (isBrowser) return window.sessionStorage.getItem(k);
        return global.__mockSession ? global.__mockSession[k] : null;
      },
      setItem(k, v) {
        if (isBrowser) window.sessionStorage.setItem(k, v);
        else {
          global.__mockSession = global.__mockSession || {};
          global.__mockSession[k] = String(v);
        }
      },
      removeItem(k) {
        if (isBrowser) window.sessionStorage.removeItem(k);
        else if (global.__mockSession) delete global.__mockSession[k];
      }
    }
  };

  // Web Crypto access
  const cryptoObj = (function () {
    if (isBrowser && window.crypto && window.crypto.subtle) return window.crypto;
    if (typeof require !== 'undefined') {
      try {
        const c = require('crypto');
        if (c.webcrypto) return c.webcrypto;
        return c;
      } catch (e) {}
    }
    return null;
  })();

  const CONFIG = {
    SESSION_KEY: 'santander_auth_session',
    USERS_KEY: 'santander_auth_users',
    LOCKOUT_KEY: 'santander_auth_lockout',
    ASYNC_ASESORES_KEY: 'santander_asesores_locales',
    MAX_FAILED_ATTEMPTS: 5,
    LOCKOUT_DURATION_MS: 15 * 60 * 1000, // 15 minutos
    INACTIVITY_TIMEOUT_MS: 2 * 60 * 60 * 1000, // 2 horas
    PBKDF2_ITERATIONS: 100000,
    SALT_ADMIN: 's4nt4nd3r_adm1n_s4lt_2026',
    HASH_ADMIN: '06fb650db0a6738cc2ddb03e0616bd2b25e37399b614ac82cd1a10673fe65ea8',
    SALT_ASESOR: 's4nt4nd3r_4s3s0r_s4lt_2026',
    HASH_ASESOR: '878c0c6beada60a0ec7bbcb44005554292c60d8eebe0581f891db81cb525eaad'
  };

  /**
   * Cryptographic Functions (PBKDF2 with SHA-256)
   */
  async function generateSalt(length = 16) {
    if (cryptoObj && cryptoObj.getRandomValues) {
      const arr = new Uint8Array(length);
      cryptoObj.getRandomValues(arr);
      return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // Fallback pseudo-random
    let s = '';
    for (let i = 0; i < length * 2; i++) {
      s += Math.floor(Math.random() * 16).toString(16);
    }
    return s;
  }

  async function hashPassword(password, salt) {
    if (!cryptoObj || !cryptoObj.subtle) {
      throw new Error('Web Crypto API no disponible en este entorno.');
    }
    const enc = new TextEncoder();
    const keyMaterial = await cryptoObj.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const derivedBits = await cryptoObj.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: enc.encode(salt),
        iterations: CONFIG.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );
    const hashArray = Array.from(new Uint8Array(derivedBits));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Initial Seeds: Carmen Coloma (Admin) + 8 Asesores Oficiales
   */
  const SEED_USERS = [
    {
      id: 'carmen',
      nombre: 'Carmen Coloma',
      email: 'carmen.coloma@santandervip.gt',
      tel: '50252945088',
      puesto: 'Directora Comercial & VIP Estates',
      avatar: 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=400&q=80',
      rol: 'admin',
      estado: 'activo',
      salt: CONFIG.SALT_ADMIN,
      passwordHash: CONFIG.HASH_ADMIN,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'santiago',
      nombre: 'Santiago Leoni',
      email: 'santiago.leoni@santandervip.gt',
      tel: '50231507820',
      puesto: 'Especialista en Residencias de Lujo',
      avatar: 'https://images.unsplash.com/photo-1560250097-0b93528c311a?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'joseluis',
      nombre: 'Jose Luis Coloma',
      email: 'joseluis.coloma@santandervip.gt',
      tel: '50258365894',
      puesto: 'Director Inmobiliario Senior',
      avatar: 'https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'madeleine',
      nombre: 'Madeleine Mazat',
      email: 'madeleine.mazat@santandervip.gt',
      tel: '50250174606',
      puesto: 'Asesora Senior de Inversiones',
      avatar: 'https://images.unsplash.com/photo-1580489944761-15a19d654956?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'mariaelena',
      nombre: 'Maria Elena de Ruiz',
      email: 'mariaelena.ruiz@santandervip.gt',
      tel: '50255237951',
      puesto: 'Consultora Inmobiliaria Exclusiva',
      avatar: 'https://images.unsplash.com/photo-1567532939604-b6b5b0db2604?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'bitia',
      nombre: 'Bitia Carballo',
      email: 'bitia.carballo@santandervip.gt',
      tel: '50256324236',
      puesto: 'Especialista en Rentas Corporativas',
      avatar: 'https://images.unsplash.com/photo-1573497019940-1c28c88b4f3e?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'sonia',
      nombre: 'Sonia Mejía',
      email: 'sonia.mejia@santandervip.gt',
      tel: '50241191773',
      puesto: 'Asesora Patrimonial Senior',
      avatar: 'https://images.unsplash.com/photo-1598550874175-4d0ef436c909?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'sofia',
      nombre: 'Sofia Deón',
      email: 'sofia.deon@santandervip.gt',
      tel: '50230001208',
      puesto: 'Especialista en Desarrollos VIP',
      avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    },
    {
      id: 'william',
      nombre: 'William Cabrera',
      email: 'william.cabrera@santandervip.gt',
      tel: '50255105971',
      puesto: 'Consultor de Propiedades de Lujo',
      avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&w=400&q=80',
      rol: 'asesor',
      estado: 'activo',
      salt: CONFIG.SALT_ASESOR,
      passwordHash: CONFIG.HASH_ASESOR,
      creadoEn: '2026-01-01T00:00:00.000Z',
      ultimoAcceso: null
    }
  ];

  /**
   * Database Store Helpers
   */
  function getUsersStore() {
    try {
      const raw = storage.local.getItem(CONFIG.USERS_KEY);
      if (!raw) {
        saveUsersStore(SEED_USERS);
        return [...SEED_USERS];
      }
      const users = JSON.parse(raw);
      // Ensure Carmen exists
      if (!users.some(u => u.id === 'carmen')) {
        users.unshift(SEED_USERS[0]);
        saveUsersStore(users);
      }
      return users;
    } catch (e) {
      console.warn('Error leyendo almacén de usuarios:', e);
      return [...SEED_USERS];
    }
  }

  function saveUsersStore(users) {
    try {
      storage.local.setItem(CONFIG.USERS_KEY, JSON.stringify(users));
    } catch (e) {
      console.error('Error guardando almacén de usuarios:', e);
    }
  }

  /**
   * Anti-Brute Force Lockout Management
   */
  function getLockoutStatus() {
    try {
      const raw = storage.local.getItem(CONFIG.LOCKOUT_KEY);
      if (!raw) return { isLocked: false, remainingMs: 0, attempts: 0 };
      const data = JSON.parse(raw);
      const now = Date.now();
      if (data.lockedUntil && now < data.lockedUntil) {
        return {
          isLocked: true,
          remainingMs: data.lockedUntil - now,
          attempts: data.attempts || CONFIG.MAX_FAILED_ATTEMPTS
        };
      }
      // Si el tiempo expiró, limpiar candado pero mantener limpio
      if (data.lockedUntil && now >= data.lockedUntil) {
        clearLockout();
        return { isLocked: false, remainingMs: 0, attempts: 0 };
      }
      return {
        isLocked: false,
        remainingMs: 0,
        attempts: data.attempts || 0
      };
    } catch (e) {
      return { isLocked: false, remainingMs: 0, attempts: 0 };
    }
  }

  function recordFailedAttempt() {
    try {
      const status = getLockoutStatus();
      const attempts = (status.attempts || 0) + 1;
      const now = Date.now();
      const isNowLocked = attempts >= CONFIG.MAX_FAILED_ATTEMPTS;
      const lockedUntil = isNowLocked ? now + CONFIG.LOCKOUT_DURATION_MS : null;

      storage.local.setItem(CONFIG.LOCKOUT_KEY, JSON.stringify({
        attempts,
        lockedUntil,
        lastFailedAt: now
      }));

      return {
        isLocked: isNowLocked,
        remainingMs: isNowLocked ? CONFIG.LOCKOUT_DURATION_MS : 0,
        attemptsLeft: Math.max(0, CONFIG.MAX_FAILED_ATTEMPTS - attempts)
      };
    } catch (e) {
      return { isLocked: false, remainingMs: 0, attemptsLeft: 0 };
    }
  }

  function clearLockout() {
    try {
      storage.local.removeItem(CONFIG.LOCKOUT_KEY);
    } catch (e) {}
  }

  /**
   * Session Management & Route Guards
   */
  function createSession(user, rememberMe = false) {
    const now = Date.now();
    const session = {
      token: 'jwt_santander_' + Math.random().toString(36).substring(2) + '_' + now,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        tel: user.tel,
        puesto: user.puesto,
        avatar: user.avatar,
        rol: user.rol,
        estado: user.estado
      },
      rememberMe: !!rememberMe,
      loginAt: now,
      lastActivity: now,
      expiresAt: now + (rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)
    };

    const serialized = JSON.stringify(session);
    storage.session.setItem(CONFIG.SESSION_KEY, serialized);
    if (rememberMe) {
      storage.local.setItem(CONFIG.SESSION_KEY, serialized);
    } else {
      storage.local.removeItem(CONFIG.SESSION_KEY);
    }

    return session;
  }

  function getSession() {
    try {
      const raw = storage.session.getItem(CONFIG.SESSION_KEY) || storage.local.getItem(CONFIG.SESSION_KEY);
      if (!raw) return null;
      const session = JSON.parse(raw);
      const now = Date.now();

      // Verificar expiración dura
      if (session.expiresAt && now > session.expiresAt) {
        destroySession();
        return null;
      }

      // Verificar inactividad (2 horas)
      if (session.lastActivity && (now - session.lastActivity > CONFIG.INACTIVITY_TIMEOUT_MS)) {
        destroySession();
        return null;
      }

      return session;
    } catch (e) {
      return null;
    }
  }

  function recordActivity() {
    try {
      const session = getSession();
      if (!session) return;
      const now = Date.now();
      // Throttling: solo actualizar cada 15 segundos
      if (now - session.lastActivity < 15000) return;

      session.lastActivity = now;
      const serialized = JSON.stringify(session);
      storage.session.setItem(CONFIG.SESSION_KEY, serialized);
      if (session.rememberMe) {
        storage.local.setItem(CONFIG.SESSION_KEY, serialized);
      }
    } catch (e) {}
  }

  function destroySession() {
    try {
      storage.session.removeItem(CONFIG.SESSION_KEY);
      storage.local.removeItem(CONFIG.SESSION_KEY);
    } catch (e) {}
  }

  /**
   * Synchronization with Asesores Catalog
   */
  function syncUserWithAsesoresLocales(user) {
    if (!isBrowser) return;
    try {
      let locales = JSON.parse(storage.local.getItem(CONFIG.ASYNC_ASESORES_KEY) || '{}');
      locales[user.id] = {
        nombre: user.nombre,
        tel: user.tel,
        puesto: user.puesto,
        avatar: user.avatar,
        email: user.email
      };
      storage.local.setItem(CONFIG.ASYNC_ASESORES_KEY, JSON.stringify(locales));
    } catch (e) {
      console.warn('Error sincronizando con santander_asesores_locales:', e);
    }
  }

  /**
   * Public API
   */
  const SantanderAuth = {
    // Info & Constants
    CONFIG,

    // Inicializar almacén si no existe
    init() {
      getUsersStore();
      return this;
    },

    // Obtener estado de bloqueo anti-fuerza bruta
    getLockoutStatus,
    clearLockout,

    // Login seguro con PBKDF2
    async login(identifier, password, rememberMe = false) {
      // 1. Verificar Anti-Brute Force
      const lockout = getLockoutStatus();
      if (lockout.isLocked) {
        const mins = Math.ceil(lockout.remainingMs / 60000);
        return {
          success: false,
          locked: true,
          remainingMs: lockout.remainingMs,
          error: `Acceso temporalmente bloqueado por 15 minutos tras 5 intentos fallidos. Intenta nuevamente en ${mins} min.`
        };
      }

      if (!identifier || !password) {
        return { success: false, error: 'Por favor ingresa usuario/correo y contraseña.' };
      }

      const cleanId = String(identifier).trim().toLowerCase();
      const users = getUsersStore();

      // Buscar usuario por email, id de asesor o nombre completo
      const user = users.find(u => 
        (u.email && u.email.toLowerCase() === cleanId) || 
        (u.id && u.id.toLowerCase() === cleanId) ||
        (u.nombre && u.nombre.toLowerCase() === cleanId)
      );

      if (!user) {
        const fail = recordFailedAttempt();
        if (fail.isLocked) {
          return {
            success: false,
            locked: true,
            remainingMs: CONFIG.LOCKOUT_DURATION_MS,
            error: 'Límite de 5 intentos fallidos alcanzado. Interfaz bloqueada por 15 minutos.'
          };
        }
        return {
          success: false,
          error: `Credenciales inválidas. Te quedan ${fail.attemptsLeft} intentos antes del bloqueo temporal.`
        };
      }

      // 2. Verificar si la cuenta está suspendida por el Admin
      if (user.estado === 'suspendido') {
        return {
          success: false,
          error: 'Esta cuenta ha sido suspendida por la administración de Santander Real Estate. Contacta a Carmen Coloma.'
        };
      }

      // 3. Verificar Contraseña con PBKDF2
      try {
        const inputHash = await hashPassword(password, user.salt);
        if (inputHash !== user.passwordHash) {
          const fail = recordFailedAttempt();
          if (fail.isLocked) {
            return {
              success: false,
              locked: true,
              remainingMs: CONFIG.LOCKOUT_DURATION_MS,
              error: 'Límite de 5 intentos fallidos alcanzado. Interfaz bloqueada por 15 minutos.'
            };
          }
          return {
            success: false,
            error: `Contraseña incorrecta. Te quedan ${fail.attemptsLeft} intentos antes del bloqueo de seguridad.`
          };
        }

        // Éxito: Limpiar candado de intentos fallidos
        clearLockout();

        // Actualizar último acceso
        user.ultimoAcceso = new Date().toISOString();
        saveUsersStore(users);

        // Crear sesión segura
        const session = createSession(user, rememberMe);

        return {
          success: true,
          user: session.user,
          token: session.token
        };
      } catch (err) {
        console.error('Error durante verificación criptográfica:', err);
        return { success: false, error: 'Error del sistema criptográfico al validar credenciales.' };
      }
    },

    // Cerrar sesión
    logout(reason = 'manual') {
      destroySession();
      if (isBrowser) {
        const query = reason ? `?reason=${encodeURIComponent(reason)}` : '';
        window.location.replace(`login.html${query}`);
      }
    },

    // Obtener usuario actualmente autenticado
    getCurrentUser() {
      const s = getSession();
      return s ? s.user : null;
    },

    // Obtener sesión completa
    getSession,

    // Helpers de rol
    isAuthenticated() {
      return !!getSession();
    },

    isAdmin() {
      const u = this.getCurrentUser();
      return !!(u && u.rol === 'admin');
    },

    isAsesor() {
      const u = this.getCurrentUser();
      return !!(u && u.rol === 'asesor');
    },

    // Route Guard para páginas protegidas (admin.html, panel.html)
    requireAuth(options = {}) {
      if (!isBrowser) return null;
      const session = getSession();
      if (!session) {
        window.location.replace('login.html?reason=unauthorized');
        return null;
      }

      if (options.requiredRole && session.user.rol !== options.requiredRole) {
        console.warn(`Acceso denegado: se requiere rol ${options.requiredRole}`);
        if (options.redirectOnRoleFail) {
          window.location.replace(options.redirectOnRoleFail);
        }
        return null;
      }

      return session.user;
    },

    // Iniciar monitor de actividad para el auto-logout de 2 horas
    startInactivityMonitor(onTimeout) {
      if (!isBrowser) return;

      const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
      const handler = () => recordActivity();

      events.forEach(evt => window.addEventListener(evt, handler, { passive: true }));

      // Revisión cada 30 segundos
      const interval = setInterval(() => {
        const session = getSession();
        if (!session) {
          clearInterval(interval);
          if (typeof onTimeout === 'function') onTimeout();
          else SantanderAuth.logout('inactivity');
        }
      }, 30000);

      return () => {
        events.forEach(evt => window.removeEventListener(evt, handler));
        clearInterval(interval);
      };
    },

    // ========================================================================
    // GESTIÓN DE USUARIOS (Módulo Exclusivo para Carmen / Admin Global)
    // ========================================================================
    getUsers() {
      const current = this.getCurrentUser();
      if (!current || current.rol !== 'admin') {
        throw new Error('Permiso denegado: solo Administradores pueden consultar la lista completa de usuarios.');
      }
      return getUsersStore().map(u => ({
        id: u.id,
        nombre: u.nombre,
        email: u.email,
        tel: u.tel,
        puesto: u.puesto,
        avatar: u.avatar,
        rol: u.rol,
        estado: u.estado,
        creadoEn: u.creadoEn,
        ultimoAcceso: u.ultimoAcceso
      }));
    },

    async createUser(userData) {
      const current = this.getCurrentUser();
      if (!current || current.rol !== 'admin') {
        throw new Error('Permiso denegado: solo Administradores pueden crear usuarios.');
      }

      const { nombre, email, tel, puesto, rol, password, avatar } = userData;
      if (!nombre || !email || !password) {
        throw new Error('Nombre, correo y contraseña son obligatorios.');
      }

      const users = getUsersStore();
      const cleanEmail = email.trim().toLowerCase();
      if (users.some(u => u.email.toLowerCase() === cleanEmail)) {
        throw new Error(`El correo ${email} ya está registrado.`);
      }

      const id = nombre.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 15) || ('user_' + Date.now());
      const salt = await generateSalt();
      const passwordHash = await hashPassword(password, salt);

      const newUser = {
        id,
        nombre: nombre.trim(),
        email: cleanEmail,
        tel: (tel || '').trim() || '50200000000',
        puesto: (puesto || 'Asesor Inmobiliario VIP').trim(),
        avatar: (avatar || '').trim() || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=400&q=80',
        rol: rol === 'admin' ? 'admin' : 'asesor',
        estado: 'activo',
        salt,
        passwordHash,
        creadoEn: new Date().toISOString(),
        ultimoAcceso: null
      };

      users.push(newUser);
      saveUsersStore(users);

      // Si es asesor, registrarlo en santander_asesores_locales
      if (newUser.rol === 'asesor') {
        syncUserWithAsesoresLocales(newUser);
      }

      return newUser;
    },

    toggleUserStatus(userId) {
      const current = this.getCurrentUser();
      if (!current || current.rol !== 'admin') {
        throw new Error('Permiso denegado: solo Administradores pueden suspender o activar cuentas.');
      }
      if (userId === 'carmen') {
        throw new Error('No es posible suspender la cuenta de la Administradora Principal.');
      }

      const users = getUsersStore();
      const user = users.find(u => u.id === userId);
      if (!user) throw new Error('Usuario no encontrado.');

      user.estado = user.estado === 'activo' ? 'suspendido' : 'activo';
      saveUsersStore(users);
      return user;
    },

    async resetUserPassword(userId, newPassword) {
      const current = this.getCurrentUser();
      if (!current || current.rol !== 'admin') {
        throw new Error('Permiso denegado: solo Administradores pueden resetear contraseñas ajenas.');
      }
      if (!newPassword || newPassword.length < 6) {
        throw new Error('La nueva contraseña debe tener al menos 6 caracteres.');
      }

      const users = getUsersStore();
      const user = users.find(u => u.id === userId);
      if (!user) throw new Error('Usuario no encontrado.');

      const newSalt = await generateSalt();
      const newHash = await hashPassword(newPassword, newSalt);

      user.salt = newSalt;
      user.passwordHash = newHash;
      saveUsersStore(users);
      return true;
    },

    // ========================================================================
    // MODAL "MI PERFIL" (Para Asesores y Administrador)
    // ========================================================================
    async updateProfile(userId, { nombre, tel, puesto, avatar }) {
      const current = this.getCurrentUser();
      if (!current || (current.id !== userId && current.rol !== 'admin')) {
        throw new Error('Permiso denegado: no puedes editar este perfil.');
      }

      const users = getUsersStore();
      const user = users.find(u => u.id === userId);
      if (!user) throw new Error('Usuario no encontrado.');

      if (nombre) user.nombre = nombre.trim();
      if (tel) user.tel = tel.trim();
      if (puesto) user.puesto = puesto.trim();
      if (avatar) user.avatar = avatar.trim();

      saveUsersStore(users);

      // Si el usuario editado es quien tiene la sesión abierta, actualizar sesión activa
      if (current.id === userId) {
        const session = getSession();
        if (session) {
          session.user.nombre = user.nombre;
          session.user.tel = user.tel;
          session.user.puesto = user.puesto;
          session.user.avatar = user.avatar;
          const serialized = JSON.stringify(session);
          storage.session.setItem(CONFIG.SESSION_KEY, serialized);
          if (session.rememberMe) storage.local.setItem(CONFIG.SESSION_KEY, serialized);
        }
      }

      // Sincronizar con catálogo de asesores
      syncUserWithAsesoresLocales(user);

      return user;
    },

    async changeOwnPassword(userId, currentPassword, newPassword) {
      const current = this.getCurrentUser();
      if (!current || current.id !== userId) {
        throw new Error('Permiso denegado: solo puedes cambiar tu propia contraseña.');
      }
      if (!newPassword || newPassword.length < 6) {
        throw new Error('La nueva contraseña debe tener al menos 6 caracteres.');
      }

      const users = getUsersStore();
      const user = users.find(u => u.id === userId);
      if (!user) throw new Error('Usuario no encontrado.');

      // Validar contraseña actual
      const currentHash = await hashPassword(currentPassword, user.salt);
      if (currentHash !== user.passwordHash) {
        throw new Error('La contraseña actual ingresada es incorrecta.');
      }

      // Generar nuevo salt y hash
      const newSalt = await generateSalt();
      const newHash = await hashPassword(newPassword, newSalt);

      user.salt = newSalt;
      user.passwordHash = newHash;
      saveUsersStore(users);

      return true;
    }
  };

  // Expose to window / global
  if (isBrowser) {
    window.SantanderAuth = SantanderAuth;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = SantanderAuth;
  }

})(typeof window !== 'undefined' ? window : globalThis);
