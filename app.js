// 台灣房東系統 API - 完整版本
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;
const API_PREFIX = process.env.API_PREFIX || '/api';

// 環境變數
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost/taiwan_landlord';

// 資料庫連接池
console.log('資料庫連接字串:', DATABASE_URL ? '已設置' : '未設置');
const poolConfig = {
  connectionString: DATABASE_URL,
  // Zeabur 的 PostgreSQL 可能不支持 SSL，所以禁用 SSL
  ssl: false,
  // 增加連接超時和重試
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 20
};

// 如果是本地開發，可以啟用 SSL
if (process.env.NODE_ENV === 'production' && DATABASE_URL && DATABASE_URL.includes('amazonaws.com')) {
  poolConfig.ssl = { rejectUnauthorized: false };
}

const pool = new Pool(poolConfig);

// 自動創建資料庫表（如果不存在）
async function initializeDatabase() {
  try {
    console.log('正在初始化資料庫表...');
    
    // 創建 users 表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'viewer',
        full_name VARCHAR(100),
        email VARCHAR(100),
        phone VARCHAR(20),
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        last_login TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // 創建 properties 表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS properties (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        address TEXT,
        owner_name VARCHAR(100),
        owner_phone VARCHAR(20),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // 創建 operation_logs 表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS operation_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action_type VARCHAR(50) NOT NULL,
        resource_type VARCHAR(50) NOT NULL,
        resource_id INTEGER,
        details JSONB,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // 創建 audit_logs 表（登入日誌）
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        username VARCHAR(50) NOT NULL,
        action VARCHAR(50) NOT NULL, -- 'login', 'logout', 'login_failed'
        ip_address VARCHAR(45), -- 支持 IPv6
        user_agent TEXT,
        success BOOLEAN NOT NULL DEFAULT false,
        error_message TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // 創建 user_sessions 表（會話管理）
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        session_token VARCHAR(255) UNIQUE NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        expires_at TIMESTAMP NOT NULL,
        last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('資料庫表初始化完成！');
  } catch (error) {
    console.error('資料庫初始化錯誤:', error.message);
  }
}

// 啟動時初始化資料庫
initializeDatabase();

// 中間件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 簡單日誌
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// CORS 中間件
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ==================== 健康檢查 ====================
app.get('/health', async (req, res) => {
  try {
    // 測試資料庫連接
    const dbResult = await pool.query('SELECT 1 as test');
    const dbConnected = dbResult.rows[0].test === 1;
    
    res.json({
      status: 'healthy',
      service: '台灣房東系統 API',
      version: '1.0.0',
      database: dbConnected ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString(),
      endpoints: {
        health: '/health',
        api_docs: '/api-docs',
        auth_register: `${API_PREFIX}/auth/register`,
        auth_login: `${API_PREFIX}/auth/login`,
        test: `${API_PREFIX}/test`
      },
      environment: {
        database_url_set: !!DATABASE_URL,
        jwt_secret_set: !!JWT_SECRET,
        api_prefix: API_PREFIX
      }
    });
  } catch (error) {
    console.error('健康檢查錯誤:', error.message);
    res.json({
      status: 'unhealthy',
      service: '台灣房東系統 API',
      error: '資料庫連接失敗',
      error_details: error.message,
      timestamp: new Date().toISOString(),
      environment: {
        database_url_set: !!DATABASE_URL,
        jwt_secret_set: !!JWT_SECRET,
        api_prefix: API_PREFIX
      }
    });
  }
});

// ==================== 根路徑 ====================
app.get('/', (req, res) => {
  res.json({
    message: '台灣房東系統 API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      api_docs: '/api-docs',
      auth_register: `${API_PREFIX}/auth/register`,
      auth_login: `${API_PREFIX}/auth/login`,
      test: `${API_PREFIX}/test`
    },
    documentation: '訪問 /api-docs 查看完整 API 文檔'
  });
});

// ==================== API 文檔 ====================
app.get('/api-docs', (req, res) => {
  res.json({
    name: '台灣房東-越南租客系統 API',
    version: '1.0.0',
    base_url: `${req.protocol}://${req.headers.host}${API_PREFIX}`,
    authentication: 'Bearer Token',
    database: 'PostgreSQL',
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        me: 'GET /auth/me (需要 Token)'
      },
      users: {
        list: 'GET /users (需要 super_admin)',
        get: 'GET /users/:id'
      },
      properties: {
        create: 'POST /properties (需要 admin)',
        list: 'GET /properties',
        get: 'GET /properties/:id'
      }
    }
  });
});

// ==================== 認證中間件 ====================
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: '未授權',
        message: '需要 Token 認證'
      });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // 驗證用戶是否存在
    const userResult = await pool.query(
      'SELECT id, username, role, status FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶不存在'
      });
    }
    
    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role
    };
    
    next();
  } catch (error) {
    console.error('認證錯誤:', error);
    res.status(401).json({
      success: false,
      error: '認證失敗',
      message: 'Token 無效或已過期'
    });
  }
};

// ==================== 角色授權中間件 ====================
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: '未授權',
        message: '需要先認證'
      });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: '權限不足',
        message: `需要 ${allowedRoles.join(' 或 ')} 權限`
      });
    }
    
    next();
  };
};

// ==================== 用戶註冊 ====================
app.post(`${API_PREFIX}/auth/register`, async (req, res) => {
  try {
    const { username, password, role = 'viewer', full_name } = req.body;
    
    // 驗證輸入
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供用戶名和密碼'
      });
    }
    
    // 檢查用戶名是否已存在
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: '用戶已存在',
        message: '用戶名已存在'
      });
    }
    
    // 哈希密碼
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 創建用戶
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role, full_name, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, role, full_name, status, created_at`,
      [username, hashedPassword, role, full_name || username, 'active']
    );
    
    const user = result.rows[0];
    
    // 生成 JWT Token
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          full_name: user.full_name,
          status: user.status,
          created_at: user.created_at
        },
        token
      },
      message: '註冊成功'
    });
    
  } catch (error) {
    console.error('註冊錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '註冊失敗'
    });
  }
});

// ==================== 用戶登入 ====================
app.post(`${API_PREFIX}/auth/login`, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供用戶名和密碼'
      });
    }
    
    // 查找用戶
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (result.rows.length === 0) {
      // 記錄登入失敗日誌（用戶不存在）
      try {
        const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        
        await pool.query(
          `INSERT INTO audit_logs (username, action, ip_address, user_agent, success, error_message)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [username, 'login_failed', ipAddress, userAgent, false, '用戶不存在']
        );
      } catch (logError) {
        console.error('記錄登入失敗日誌失敗:', logError);
      }
      
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶名或密碼錯誤'
      });
    }
    
    const user = result.rows[0];
    
    // 驗證密碼
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      // 記錄登入失敗日誌（密碼錯誤）
      try {
        const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        
        await pool.query(
          `INSERT INTO audit_logs (user_id, username, action, ip_address, user_agent, success, error_message)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [user.id, user.username, 'login_failed', ipAddress, userAgent, false, '密碼錯誤']
        );
      } catch (logError) {
        console.error('記錄登入失敗日誌失敗:', logError);
      }
      
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶名或密碼錯誤'
      });
    }
    
    // 生成 JWT Token
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // 記錄登入日誌
    try {
      const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      const userAgent = req.headers['user-agent'] || '';
      
      await pool.query(
        `INSERT INTO audit_logs (user_id, username, action, ip_address, user_agent, success)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [user.id, user.username, 'login', ipAddress, userAgent, true]
      );
      
      // 更新用戶最後登入時間
      await pool.query(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
        [user.id]
      );
    } catch (logError) {
      console.error('記錄登入日誌失敗:', logError);
      // 不影響主要登入流程
    }
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          full_name: user.full_name,
          status: user.status
        },
        token
      },
      message: '登入成功'
    });
    
  } catch (error) {
    console.error('登入錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '登入失敗'
    });
  }
});

// ==================== 獲取當前用戶信息 ====================
app.get(`${API_PREFIX}/auth/me`, authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, full_name, status, created_at
       FROM users WHERE id = $1`,
      [req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: '用戶不存在',
        message: '用戶已被刪除'
      });
    }
    
    const user = result.rows[0];
    
    res.json({
      success: true,
      data: { user },
      message: '獲取用戶信息成功'
    });
    
  } catch (error) {
    console.error('獲取用戶信息錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取用戶信息失敗'
    });
  }
});

// ==================== 創建物業 ====================
app.post(`${API_PREFIX}/properties`, authenticate, authorize('super_admin', 'admin'), async (req, res) => {
  try {
    const { name, address, owner_name, owner_phone } = req.body;
    
    if (!name) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供物業名稱'
      });
    }
    
    const result = await pool.query(
      `INSERT INTO properties (name, address, owner_name, owner_phone)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, address, owner_name, owner_phone]
    );
    
    const property = result.rows[0];
    
    res.status(201).json({
      success: true,
      data: { property },
      message: '創建物業成功'
    });
    
  } catch (error) {
    console.error('創建物業錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '創建物業失敗'
    });
  }
});

// ==================== 獲取物業列表 ====================
app.get(`${API_PREFIX}/properties`, authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM properties ORDER BY created_at DESC'
    );
    
    res.json({
      success: true,
      data: {
        properties: result.rows,
        count: result.rows.length
      },
      message: '獲取物業列表成功'
    });
    
  } catch (error) {
    console.error('獲取物業列表錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取物業列表失敗'
    });
  }
});

// ==================== 測試端點 ====================
app.get(`${API_PREFIX}/test`, async (req, res) => {
  try {
    // 嘗試連接資料庫
    let dbStatus = 'unknown';
    try {
      await pool.query('SELECT 1');
      dbStatus = 'connected';
    } catch (dbError) {
      dbStatus = `disconnected: ${dbError.message}`;
    }
    
    res.json({
      success: true,
      message: '🎉 API 測試成功！',
      data: {
        service: '台灣房東-越南租客系統',
        version: '1.0.0',
        status: 'active',
        time: new Date().toISOString(),
        database: dbStatus,
        environment: {
          database_url_set: !!DATABASE_URL,
          jwt_secret_set: !!JWT_SECRET,
          api_prefix: API_PREFIX,
          port: port
        }
      },
      endpoints: {
        health: '/health',
        api_docs: '/api-docs',
        auth_register: `${API_PREFIX}/auth/register`,
        auth_login: `${API_PREFIX}/auth/login`,
        properties_list: `${API_PREFIX}/properties (需要 Token)`,
        admin_users_list: `${API_PREFIX}/admin/users (需要管理員權限)`,
        admin_users_update: `${API_PREFIX}/admin/users/:id (需要管理員權限)`,
        admin_users_disable: `${API_PREFIX}/admin/users/:id (需要管理員權限)`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: '測試失敗',
      message: error.message
    });
  }
});

// ==================== 用戶管理 API ====================

// 獲取用戶列表（管理員以上）
app.get(`${API_PREFIX}/admin/users`, authenticate, authorize('super_admin', 'admin'), async (req, res) => {
  try {
    const { search, role, status, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    let query = 'SELECT id, username, role, full_name, email, phone, status, last_login, created_at FROM users';
    let conditions = [];
    let params = [];
    let paramCount = 0;
    
    // 搜索條件
    if (search) {
      paramCount++;
      conditions.push(`(username ILIKE $${paramCount} OR full_name ILIKE $${paramCount})`);
      params.push(`%${search}%`);
    }
    
    if (role) {
      paramCount++;
      conditions.push(`role = $${paramCount}`);
      params.push(role);
    }
    
    if (status) {
      paramCount++;
      conditions.push(`status = $${paramCount}`);
      params.push(status);
    }
    
    // 構建 WHERE 子句
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    // 排序和分頁
    query += ' ORDER BY created_at DESC';
    query += ` LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);
    
    // 執行查詢
    const result = await pool.query(query, params);
    
    // 獲取總數
    let countQuery = 'SELECT COUNT(*) as total FROM users';
    if (conditions.length > 0) {
      countQuery += ' WHERE ' + conditions.join(' AND ');
    }
    const countResult = await pool.query(countQuery, params.slice(0, paramCount));
    const total = parseInt(countResult.rows[0].total);
    
    res.json({
      success: true,
      data: {
        users: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages: Math.ceil(total / limit)
        }
      },
      message: '獲取用戶列表成功'
    });
    
  } catch (error) {
    console.error('獲取用戶列表錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取用戶列表失敗'
    });
  }
});

// 更新用戶信息（管理員以上）
app.put(`${API_PREFIX}/admin/users/:id`, authenticate, authorize('super_admin', 'admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { role, status, full_name, email, phone } = req.body;
    
    if (!userId || isNaN(userId)) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '用戶ID無效'
      });
    }
    
    // 檢查用戶是否存在
    const userCheck = await pool.query(
      'SELECT id, username FROM users WHERE id = $1',
      [userId]
    );
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: '用戶不存在',
        message: '找不到指定的用戶'
      });
    }
    
    // 構建更新字段
    const updates = [];
    const params = [];
    let paramCount = 0;
    
    if (role !== undefined) {
      // 驗證角色
      const validRoles = ['super_admin', 'admin', 'viewer'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          error: '參數錯誤',
          message: `角色必須是: ${validRoles.join(', ')}`
        });
      }
      paramCount++;
      updates.push(`role = $${paramCount}`);
      params.push(role);
    }
    
    if (status !== undefined) {
      // 驗證狀態
      const validStatuses = ['active', 'inactive', 'suspended'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          error: '參數錯誤',
          message: `狀態必須是: ${validStatuses.join(', ')}`
        });
      }
      paramCount++;
      updates.push(`status = $${paramCount}`);
      params.push(status);
    }
    
    if (full_name !== undefined) {
      paramCount++;
      updates.push(`full_name = $${paramCount}`);
      params.push(full_name);
    }
    
    if (email !== undefined) {
      paramCount++;
      updates.push(`email = $${paramCount}`);
      params.push(email);
    }
    
    if (phone !== undefined) {
      paramCount++;
      updates.push(`phone = $${paramCount}`);
      params.push(phone);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '沒有提供更新字段'
      });
    }
    
    // 添加更新時間和參數
    paramCount++;
    updates.push(`updated_at = CURRENT_TIMESTAMP`);
    
    // 添加用戶ID參數
    paramCount++;
    params.push(userId);
    
    // 執行更新
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount} RETURNING id, username, role, full_name, email, phone, status, updated_at`;
    const result = await pool.query(query, params);
    
    // 記錄操作日誌
    try {
      await pool.query(
        `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
         VALUES ($1, $2, $3, $4, $5)`,
        [req.user.userId, 'update', 'user', userId, JSON.stringify({ updates })]
      );
    } catch (logError) {
      console.error('記錄操作日誌失敗:', logError);
    }
    
    res.json({
      success: true,
      data: {
        user: result.rows[0]
      },
      message: '更新用戶成功'
    });
    
  } catch (error) {
    console.error('更新用戶錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '更新用戶失敗'
    });
  }
});

// 禁用/啟用用戶（管理員以上）
app.delete(`${API_PREFIX}/admin/users/:id`, authenticate, authorize('super_admin', 'admin'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    if (!userId || isNaN(userId)) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '用戶ID無效'
      });
    }
    
    // 檢查用戶是否存在
    const userCheck = await pool.query(
      'SELECT id, username, status FROM users WHERE id = $1',
      [userId]
    );
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: '用戶不存在',
        message: '找不到指定的用戶'
      });
    }
    
    const user = userCheck.rows[0];
    
    // 不能禁用自己
    if (userId === req.user.userId) {
      return res.status(400).json({
        success: false,
        error: '操作不允許',
        message: '不能禁用自己的帳號'
      });
    }
    
    // 切換狀態
    const newStatus = user.status === 'active' ? 'inactive' : 'active';
    const action = newStatus === 'inactive' ? 'disable' : 'enable';
    
    const result = await pool.query(
      `UPDATE users SET status = $1, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $2 
       RETURNING id, username, role, status`,
      [newStatus, userId]
    );
    
    // 記錄操作日誌
    try {
      await pool.query(
        `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
         VALUES ($1, $2, $3, $4, $5)`,
        [req.user.userId, action, 'user', userId, JSON.stringify({ old_status: user.status, new_status: newStatus })]
      );
    } catch (logError) {
      console.error('記錄操作日誌失敗:', logError);
    }
    
    res.json({
      success: true,
      data: {
        user: result.rows[0],
        action: action
      },
      message: `用戶已${newStatus === 'inactive' ? '禁用' : '啟用'}`
    });
    
  } catch (error) {
    console.error('更新用戶狀態錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '更新用戶狀態失敗'
    });
  }
});

// ==================== 404 處理 ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `找不到路徑: ${req.path}`
  });
});

// ==================== 錯誤處理 ====================
app.use((err, req, res, next) => {
  console.error('伺服器錯誤:', err);
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: '伺服器內部錯誤'
  });
});

// ==================== 啟動伺服器 ====================
// Zeabur 需要監聽 0.0.0.0 而不是 localhost
const host = '0.0.0.0';
app.listen(port, host, () => {
  console.log(`🚀 台灣房東系統 API 啟動成功！`);
  console.log(`🌐 監聽: ${host}:${port}`);
  console.log(`✅ 健康檢查: http://${host}:${port}/health`);
  console.log(`📚 API 文檔: http://${host}:${port}/api-docs`);
  console.log(`🔑 註冊端點: POST http://${host}:${port}${API_PREFIX}/auth/register`);
  console.log(`🔑 登入端點: POST http://${host}:${port}${API_PREFIX}/auth/login`);
  console.log(`\n📝 環境變數:`);
  console.log(`   JWT_SECRET: ${JWT_SECRET ? '已設置' : '未設置（使用默認值）'}`);
  console.log(`   DATABASE_URL: ${DATABASE_URL ? '已設置' : '未設置（使用默認值）'}`);
  console.log(`   PORT: ${port}`);
  console.log(`   HOST: ${host}`);
});