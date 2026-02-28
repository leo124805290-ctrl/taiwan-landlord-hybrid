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
    
    // 創建 settings 表（系統設置）
    await pool.query(`
      CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(100) UNIQUE NOT NULL,
        value TEXT,
        category VARCHAR(50) NOT NULL DEFAULT 'general',
        description TEXT,
        updated_by INTEGER REFERENCES users(id),
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // 創建 backup_logs 表（數據備份記錄）
    await pool.query(`
      CREATE TABLE IF NOT EXISTS backup_logs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        file_size BIGINT,
        record_count INTEGER,
        backup_type VARCHAR(50) NOT NULL DEFAULT 'manual', -- manual, auto, scheduled
        status VARCHAR(50) NOT NULL DEFAULT 'completed', -- pending, in_progress, completed, failed
        created_by INTEGER REFERENCES users(id),
        restored_by INTEGER REFERENCES users(id),
        restored_at TIMESTAMP,
        expires_at TIMESTAMP,
        metadata JSONB,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // 插入默認設置
    const defaultSettings = [
      { key: 'system_name', value: '台灣房東系統', category: 'general', description: '系統名稱' },
      { key: 'system_language', value: 'zh-TW', category: 'general', description: '默認語言' },
      { key: 'timezone', value: 'Asia/Taipei', category: 'general', description: '時區' },
      { key: 'date_format', value: 'YYYY-MM-DD', category: 'general', description: '日期格式' },
      { key: 'currency_format', value: 'TWD', category: 'general', description: '貨幣格式' },
      { key: 'password_min_length', value: '6', category: 'security', description: '密碼最小長度' },
      { key: 'session_timeout_hours', value: '24', category: 'security', description: '會話超時時間（小時）' },
      { key: 'login_attempt_limit', value: '5', category: 'security', description: '登入嘗試限制' },
      { key: 'backup_retention_days', value: '30', category: 'backup', description: '備份保留天數' },
      { key: 'auto_backup_enabled', value: 'true', category: 'backup', description: '自動備份啟用' },
      { key: 'notification_enabled', value: 'true', category: 'notification', description: '通知啟用' }
    ];
    
    for (const setting of defaultSettings) {
      await pool.query(`
        INSERT INTO settings (key, value, category, description)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (key) DO NOTHING
      `, [setting.key, setting.value, setting.category, setting.description]);
    }
    
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

// ==================== 系統設置 API ====================

// 獲取所有系統設置（管理員以上）
app.get(`${API_PREFIX}/settings`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { category } = req.query;
    
    let query = 'SELECT * FROM settings';
    let params = [];
    
    if (category) {
      query += ' WHERE category = $1';
      params.push(category);
    }
    
    query += ' ORDER BY category, key';
    
    const result = await pool.query(query, params);
    
    // 將結果轉換為對象格式
    const settings = {};
    result.rows.forEach(row => {
      settings[row.key] = {
        value: row.value,
        category: row.category,
        description: row.description,
        updated_at: row.updated_at
      };
    });
    
    res.json({
      success: true,
      data: {
        settings,
        count: result.rows.length
      },
      message: '獲取系統設置成功'
    });
    
  } catch (error) {
    console.error('獲取系統設置錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取系統設置失敗'
    });
  }
});

// 更新系統設置（管理員以上）
app.put(`${API_PREFIX}/settings`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { settings } = req.body;
    
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '需要提供設置對象'
      });
    }
    
    const updatedSettings = [];
    const errors = [];
    
    // 遍歷所有要更新的設置
    for (const [key, valueObj] of Object.entries(settings)) {
      try {
        const value = typeof valueObj === 'object' ? valueObj.value : valueObj;
        
        // 檢查設置是否存在
        const checkResult = await pool.query(
          'SELECT id FROM settings WHERE key = $1',
          [key]
        );
        
        if (checkResult.rows.length === 0) {
          errors.push(`設置 ${key} 不存在`);
          continue;
        }
        
        // 更新設置
        const result = await pool.query(
          `UPDATE settings 
           SET value = $1, updated_by = $2, updated_at = CURRENT_TIMESTAMP
           WHERE key = $3
           RETURNING key, value, category, description, updated_at`,
          [value, req.user.userId, key]
        );
        
        updatedSettings.push(result.rows[0]);
        
        // 記錄操作日誌
        await pool.query(
          `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
           VALUES ($1, $2, $3, $4, $5)`,
          [req.user.userId, 'update', 'setting', checkResult.rows[0].id, 
           JSON.stringify({ key, old_value: checkResult.rows[0].value, new_value: value })]
        );
        
      } catch (updateError) {
        console.error(`更新設置 ${key} 錯誤:`, updateError);
        errors.push(`更新 ${key} 失敗: ${updateError.message}`);
      }
    }
    
    if (errors.length > 0 && updatedSettings.length === 0) {
      return res.status(400).json({
        success: false,
        error: '更新失敗',
        message: errors.join(', ')
      });
    }
    
    res.json({
      success: true,
      data: {
        updated: updatedSettings,
        errors: errors.length > 0 ? errors : undefined
      },
      message: `成功更新 ${updatedSettings.length} 個設置${errors.length > 0 ? `，${errors.length} 個失敗` : ''}`
    });
    
  } catch (error) {
    console.error('更新系統設置錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '更新系統設置失敗'
    });
  }
});

// 獲取特定類別的設置
app.get(`${API_PREFIX}/settings/:category`, authenticate, async (req, res) => {
  try {
    const { category } = req.params;
    
    const result = await pool.query(
      'SELECT key, value, description FROM settings WHERE category = $1 ORDER BY key',
      [category]
    );
    
    const settings = {};
    result.rows.forEach(row => {
      settings[row.key] = row.value;
    });
    
    res.json({
      success: true,
      data: {
        category,
        settings,
        count: result.rows.length
      },
      message: '獲取設置成功'
    });
    
  } catch (error) {
    console.error('獲取類別設置錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取設置失敗'
    });
  }
});

// ==================== 數據備份 API ====================

// 創建數據備份（管理員以上）
app.post(`${API_PREFIX}/backup`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { name, description } = req.body;
    
    if (!name) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '備份名稱不能為空'
      });
    }
    
    // 開始創建備份記錄
    const backupResult = await pool.query(
      `INSERT INTO backup_logs (name, description, backup_type, status, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP + INTERVAL '30 days')
       RETURNING id, name, description, backup_type, status, created_at`,
      [name, description || '手動備份', 'manual', 'completed', req.user.userId]
    );
    
    const backup = backupResult.rows[0];
    
    // 這裡應該實際執行數據庫備份操作
    // 由於這是簡化版本，我們只記錄備份請求
    
    // 記錄操作日誌
    await pool.query(
      `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.userId, 'create', 'backup', backup.id, 
       JSON.stringify({ name, description, type: 'manual' })]
    );
    
    res.json({
      success: true,
      data: {
        backup,
        message: '備份創建成功（模擬）',
        note: '在實際環境中，這裡會執行完整的數據庫備份'
      },
      message: '備份請求已提交'
    });
    
  } catch (error) {
    console.error('創建備份錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '創建備份失敗'
    });
  }
});

// 獲取備份列表（管理員以上）
app.get(`${API_PREFIX}/backups`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { status, type, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT bl.*, 
             u1.username as created_by_username,
             u2.username as restored_by_username
      FROM backup_logs bl
      LEFT JOIN users u1 ON bl.created_by = u1.id
      LEFT JOIN users u2 ON bl.restored_by = u2.id
    `;
    
    let conditions = [];
    let params = [];
    let paramCount = 0;
    
    if (status) {
      paramCount++;
      conditions.push(`bl.status = $${paramCount}`);
      params.push(status);
    }
    
    if (type) {
      paramCount++;
      conditions.push(`bl.backup_type = $${paramCount}`);
      params.push(type);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY bl.created_at DESC';
    query += ` LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);
    
    // 執行查詢
    const result = await pool.query(query, params);
    
    // 獲取總數
    let countQuery = 'SELECT COUNT(*) as total FROM backup_logs bl';
    if (conditions.length > 0) {
      countQuery += ' WHERE ' + conditions.join(' AND ');
    }
    const countResult = await pool.query(countQuery, params.slice(0, paramCount));
    const total = parseInt(countResult.rows[0].total);
    
    // 統計信息
    const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_backups,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_backups,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_backups,
        COUNT(CASE WHEN restored_at IS NOT NULL THEN 1 END) as restored_backups,
        COALESCE(SUM(file_size), 0) as total_size
      FROM backup_logs
    `);
    
    const stats = statsResult.rows[0];
    
    res.json({
      success: true,
      data: {
        backups: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages: Math.ceil(total / limit)
        },
        stats
      },
      message: '獲取備份列表成功'
    });
    
  } catch (error) {
    console.error('獲取備份列表錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取備份列表失敗'
    });
  }
});

// 恢復備份（管理員以上）
app.post(`${API_PREFIX}/backups/:id/restore`, authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const backupId = parseInt(req.params.id);
    
    if (!backupId || isNaN(backupId)) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '備份ID無效'
      });
    }
    
    // 檢查備份是否存在
    const backupCheck = await pool.query(
      `SELECT id, name, status FROM backup_logs WHERE id = $1`,
      [backupId]
    );
    
    if (backupCheck.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: '備份不存在',
        message: '找不到指定的備份'
      });
    }
    
    const backup = backupCheck.rows[0];
    
    // 檢查備份狀態
    if (backup.status !== 'completed') {
      return res.status(400).json({
        success: false,
        error: '操作不允許',
        message: '只能恢復已完成的備份'
      });
    }
    
    // 更新備份記錄
    const updateResult = await pool.query(
      `UPDATE backup_logs 
       SET restored_by = $1, restored_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, name, restored_at`,
      [req.user.userId, backupId]
    );
    
    const updatedBackup = updateResult.rows[0];
    
    // 記錄操作日誌
    await pool.query(
      `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.userId, 'restore', 'backup', backupId, 
       JSON.stringify({ backup_name: backup.name })]
    );
    
    res.json({
      success: true,
      data: {
        backup: updatedBackup,
        message: '恢復請求已提交（模擬）',
        warning: '在實際環境中，這裡會執行完整的數據庫恢復操作',
        note: '恢復操作可能需要幾分鐘時間，請勿關閉頁面'
      },
      message: '備份恢復請求已提交'
    });
    
  } catch (error) {
    console.error('恢復備份錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '恢復備份失敗'
    });
  }
});

// 刪除備份（超級管理員）
app.delete(`${API_PREFIX}/backups/:id`, authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const backupId = parseInt(req.params.id);
    
    if (!backupId || isNaN(backupId)) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '備份ID無效'
      });
    }
    
    // 檢查備份是否存在
    const backupCheck = await pool.query(
      `SELECT id, name FROM backup_logs WHERE id = $1`,
      [backupId]
    );
    
    if (backupCheck.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: '備份不存在',
        message: '找不到指定的備份'
      });
    }
    
    const backup = backupCheck.rows[0];
    
    // 刪除備份記錄
    await pool.query(
      'DELETE FROM backup_logs WHERE id = $1',
      [backupId]
    );
    
    // 記錄操作日誌
    await pool.query(
      `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.userId, 'delete', 'backup', backupId, 
       JSON.stringify({ backup_name: backup.name })]
    );
    
    res.json({
      success: true,
      data: {
        deleted_id: backupId,
        backup_name: backup.name
      },
      message: '備份已刪除'
    });
    
  } catch (error) {
    console.error('刪除備份錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '刪除備份失敗'
    });
  }
});

// 獲取備份統計信息（管理員以上）
app.get(`${API_PREFIX}/backups/stats`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const statsResult = await pool.query(`
      SELECT 
        -- 總體統計
        COUNT(*) as total_backups,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_backups,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_backups,
        COUNT(CASE WHEN restored_at IS NOT NULL THEN 1 END) as restored_backups,
        COALESCE(SUM(file_size), 0) as total_size_bytes,
        
        -- 類型統計
        COUNT(CASE WHEN backup_type = 'manual' THEN 1 END) as manual_backups,
        COUNT(CASE WHEN backup_type = 'auto' THEN 1 END) as auto_backups,
        COUNT(CASE WHEN backup_type = 'scheduled' THEN 1 END) as scheduled_backups,
        
        -- 時間統計
        COUNT(CASE WHEN created_at >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as last_7_days,
        COUNT(CASE WHEN created_at >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as last_30_days,
        
        -- 最近備份
        MAX(created_at) as last_backup_time,
        MIN(created_at) as first_backup_time
        
      FROM backup_logs
    `);
    
    const stats = statsResult.rows[0];
    
    // 計算人類可讀的大小
    const formatSize = (bytes: number) => {
      if (bytes < 1024) return `${bytes} B`;
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    };
    
    const formattedStats = {
      ...stats,
      total_size: formatSize(parseInt(stats.total_size_bytes)),
      last_backup_time: stats.last_backup_time ? new Date(stats.last_backup_time).toISOString() : null,
      first_backup_time: stats.first_backup_time ? new Date(stats.first_backup_time).toISOString() : null
    };
    
    res.json({
      success: true,
      data: {
        stats: formattedStats
      },
      message: '獲取備份統計成功'
    });
    
  } catch (error) {
    console.error('獲取備份統計錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取備份統計失敗'
    });
  }
});

// ==================== 登入日誌 API ====================

// 獲取登入日誌（管理員以上）
app.get(`${API_PREFIX}/logs/login`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { 
      user_id, 
      username, 
      action, 
      success, 
      start_date, 
      end_date, 
      page = 1, 
      limit = 50 
    } = req.query;
    
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT al.*, u.username as user_username, u.role as user_role
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
    `;
    
    let conditions = [];
    let params = [];
    let paramCount = 0;
    
    if (user_id) {
      paramCount++;
      conditions.push(`al.user_id = $${paramCount}`);
      params.push(user_id);
    }
    
    if (username) {
      paramCount++;
      conditions.push(`al.username ILIKE $${paramCount}`);
      params.push(`%${username}%`);
    }
    
    if (action) {
      paramCount++;
      conditions.push(`al.action = $${paramCount}`);
      params.push(action);
    }
    
    if (success !== undefined) {
      paramCount++;
      conditions.push(`al.success = $${paramCount}`);
      params.push(success === 'true');
    }
    
    if (start_date) {
      paramCount++;
      conditions.push(`al.created_at >= $${paramCount}`);
      params.push(start_date);
    }
    
    if (end_date) {
      paramCount++;
      conditions.push(`al.created_at <= $${paramCount}`);
      params.push(end_date);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY al.created_at DESC';
    query += ` LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);
    
    // 執行查詢
    const result = await pool.query(query, params);
    
    // 獲取總數
    let countQuery = 'SELECT COUNT(*) as total FROM audit_logs al';
    if (conditions.length > 0) {
      countQuery += ' WHERE ' + conditions.join(' AND ');
    }
    const countResult = await pool.query(countQuery, params.slice(0, paramCount));
    const total = parseInt(countResult.rows[0].total);
    
    // 統計信息
    const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_logs,
        COUNT(CASE WHEN action = 'login' AND success = true THEN 1 END) as successful_logins,
        COUNT(CASE WHEN action = 'login' AND success = false THEN 1 END) as failed_logins,
        COUNT(CASE WHEN action = 'logout' THEN 1 END) as logouts,
        COUNT(CASE WHEN action = 'login_failed' THEN 1 END) as login_failures,
        COUNT(DISTINCT user_id) as unique_users,
        COUNT(DISTINCT ip_address) as unique_ips,
        MIN(created_at) as first_login,
        MAX(created_at) as last_login
      FROM audit_logs
    `);
    
    const stats = statsResult.rows[0];
    
    // 最近24小時活動統計
    const recentStatsResult = await pool.query(`
      SELECT 
        COUNT(CASE WHEN created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours' THEN 1 END) as last_24h,
        COUNT(CASE WHEN created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days' THEN 1 END) as last_7d,
        COUNT(CASE WHEN created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days' THEN 1 END) as last_30d
      FROM audit_logs
    `);
    
    const recentStats = recentStatsResult.rows[0];
    
    res.json({
      success: true,
      data: {
        logs: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages: Math.ceil(total / limit)
        },
        stats: {
          ...stats,
          recent: recentStats
        }
      },
      message: '獲取登入日誌成功'
    });
    
  } catch (error) {
    console.error('獲取登入日誌錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取登入日誌失敗'
    });
  }
});

// 獲取操作日誌（管理員以上）
app.get(`${API_PREFIX}/logs/operation`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { 
      user_id, 
      action_type, 
      resource_type, 
      start_date, 
      end_date, 
      page = 1, 
      limit = 50 
    } = req.query;
    
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT ol.*, u.username, u.role, u.email
      FROM operation_logs ol
      LEFT JOIN users u ON ol.user_id = u.id
    `;
    
    let conditions = [];
    let params = [];
    let paramCount = 0;
    
    if (user_id) {
      paramCount++;
      conditions.push(`ol.user_id = $${paramCount}`);
      params.push(user_id);
    }
    
    if (action_type) {
      paramCount++;
      conditions.push(`ol.action_type = $${paramCount}`);
      params.push(action_type);
    }
    
    if (resource_type) {
      paramCount++;
      conditions.push(`ol.resource_type = $${paramCount}`);
      params.push(resource_type);
    }
    
    if (start_date) {
      paramCount++;
      conditions.push(`ol.created_at >= $${paramCount}`);
      params.push(start_date);
    }
    
    if (end_date) {
      paramCount++;
      conditions.push(`ol.created_at <= $${paramCount}`);
      params.push(end_date);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY ol.created_at DESC';
    query += ` LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);
    
    // 執行查詢
    const result = await pool.query(query, params);
    
    // 獲取總數
    let countQuery = 'SELECT COUNT(*) as total FROM operation_logs ol';
    if (conditions.length > 0) {
      countQuery += ' WHERE ' + conditions.join(' AND ');
    }
    const countResult = await pool.query(countQuery, params.slice(0, paramCount));
    const total = parseInt(countResult.rows[0].total);
    
    // 統計信息
    const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_operations,
        COUNT(DISTINCT user_id) as active_users,
        COUNT(DISTINCT action_type) as unique_action_types,
        COUNT(DISTINCT resource_type) as unique_resource_types,
        MIN(created_at) as first_operation,
        MAX(created_at) as last_operation
      FROM operation_logs
    `);
    
    const stats = statsResult.rows[0];
    
    // 操作類型統計
    const actionStatsResult = await pool.query(`
      SELECT 
        action_type,
        COUNT(*) as count,
        COUNT(DISTINCT user_id) as users,
        MIN(created_at) as first_time,
        MAX(created_at) as last_time
      FROM operation_logs
      GROUP BY action_type
      ORDER BY count DESC
      LIMIT 10
    `);
    
    const actionStats = actionStatsResult.rows;
    
    res.json({
      success: true,
      data: {
        logs: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages: Math.ceil(total / limit)
        },
        stats: {
          ...stats,
          action_types: actionStats
        }
      },
      message: '獲取操作日誌成功'
    });
    
  } catch (error) {
    console.error('獲取操作日誌錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取操作日誌失敗'
    });
  }
});

// 清除舊日誌（超級管理員）
app.delete(`${API_PREFIX}/logs/cleanup`, authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { days = 90 } = req.query;
    const retentionDays = parseInt(days);
    
    if (isNaN(retentionDays) || retentionDays < 7) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '保留天數必須大於等於7天'
      });
    }
    
    // 清除舊的登入日誌
    const auditDeleteResult = await pool.query(
      `DELETE FROM audit_logs WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '${retentionDays} days' RETURNING COUNT(*) as deleted_count`
    );
    
    const auditDeleted = parseInt(auditDeleteResult.rows[0].deleted_count);
    
    // 清除舊的操作日誌
    const operationDeleteResult = await pool.query(
      `DELETE FROM operation_logs WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '${retentionDays} days' RETURNING COUNT(*) as deleted_count`
    );
    
    const operationDeleted = parseInt(operationDeleteResult.rows[0].deleted_count);
    
    // 記錄清理操作
    await pool.query(
      `INSERT INTO operation_logs (user_id, action_type, resource_type, details)
       VALUES ($1, $2, $3, $4)`,
      [req.user.userId, 'cleanup', 'logs', 
       JSON.stringify({ 
         retention_days: retentionDays, 
         audit_logs_deleted: auditDeleted,
         operation_logs_deleted: operationDeleted 
       })]
    );
    
    res.json({
      success: true,
      data: {
        audit_logs_deleted: auditDeleted,
        operation_logs_deleted: operationDeleted,
        total_deleted: auditDeleted + operationDeleted,
        retention_days: retentionDays
      },
      message: `已清除 ${auditDeleted + operationDeleted} 條舊日誌（保留最近 ${retentionDays} 天）`
    });
    
  } catch (error) {
    console.error('清除日誌錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '清除日誌失敗'
    });
  }
});

// 導出日誌（管理員以上）
app.get(`${API_PREFIX}/logs/export`, authenticate, authorize('admin', 'super_admin'), async (req, res) => {
  try {
    const { type, format = 'json', start_date, end_date } = req.query;
    
    if (!type || !['login', 'operation'].includes(type)) {
      return res.status(400).json({
        success: false,
        error: '參數錯誤',
        message: '日誌類型必須是 login 或 operation'
      });
    }
    
    let query;
    let filename;
    
    if (type === 'login') {
      query = `
        SELECT al.*, u.username as user_username, u.role as user_role
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
      `;
      filename = `login_logs_${new Date().toISOString().split('T')[0]}`;
    } else {
      query = `
        SELECT ol.*, u.username, u.role, u.email
        FROM operation_logs ol
        LEFT JOIN users u ON ol.user_id = u.id
      `;
      filename = `operation_logs_${new Date().toISOString().split('T')[0]}`;
    }
    
    let conditions = [];
    let params = [];
    let paramCount = 0;
    
    if (start_date) {
      paramCount++;
      conditions.push(`created_at >= $${paramCount}`);
      params.push(start_date);
    }
    
    if (end_date) {
      paramCount++;
      conditions.push(`created_at <= $${paramCount}`);
      params.push(end_date);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY created_at DESC';
    
    const result = await pool.query(query, params);
    
    // 記錄導出操作
    await pool.query(
      `INSERT INTO operation_logs (user_id, action_type, resource_type, details)
       VALUES ($1, $2, $3, $4)`,
      [req.user.userId, 'export', 'logs', 
       JSON.stringify({ 
         log_type: type, 
         format: format,
         record_count: result.rows.length,
         date_range: { start_date, end_date }
       })]
    );
    
    if (format === 'csv') {
      // CSV 格式導出
      const headers = Object.keys(result.rows[0] || {}).join(',');
      const rows = result.rows.map(row => 
        Object.values(row).map(value => 
          typeof value === 'string' ? `"${value.replace(/"/g, '""')}"` : value
        ).join(',')
      ).join('\n');
      
      const csvContent = `${headers}\n${rows}`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}.csv"`);
      res.send(csvContent);
      
    } else {
      // JSON 格式導出（默認）
      res.json({
        success: true,
        data: {
          logs: result.rows,
          metadata: {
            type,
            format,
            count: result.rows.length,
            exported_at: new Date().toISOString(),
            exported_by: req.user.userId,
            date_range: { start_date, end_date }
          }
        },
        message: '日誌導出成功'
      });
    }
    
  } catch (error) {
    console.error('導出日誌錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '導出日誌失敗'
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