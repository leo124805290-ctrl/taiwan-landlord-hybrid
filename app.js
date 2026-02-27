// 混合版本 - JavaScript 實現完整功能
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
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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

// 健康檢查
app.get('/health', async (req, res) => {
  try {
    // 測試資料庫連接
    await pool.query('SELECT 1');
    
    res.json({
      status: 'healthy',
      service: '台灣房東系統 API (混合版本)',
      version: '1.0.0',
      database: 'connected',
      timestamp: new Date().toISOString(),
      features: ['認證系統', '用戶管理', '物業管理', 'PostgreSQL']
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      service: '台灣房東系統 API',
      error: '資料庫連接失敗',
      timestamp: new Date().toISOString()
    });
  }
});

// API 文檔
app.get('/api-docs', (req, res) => {
  res.json({
    name: '台灣房東-越南租客系統 API',
    version: '混合版本 1.0.0',
    base_url: `${req.protocol}://${req.headers.host}${API_PREFIX}`,
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        me: 'GET /auth/me (需要 Token)'
      },
      users: {
        list: 'GET /users (需要 super_admin)',
        get: 'GET /users/:id',
        update: 'PUT /users/:id'
      },
      properties: {
        create: 'POST /properties (需要 admin)',
        list: 'GET /properties',
        get: 'GET /properties/:id',
        update: 'PUT /properties/:id (需要 admin)'
      }
    },
    authentication: 'Bearer Token',
    database: 'PostgreSQL'
  });
});

// 認證中間件
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
    
    // 驗證用戶是否存在且活躍
    const userResult = await pool.query(
      'SELECT id, username, role, status FROM users WHERE id = $1 AND status = $2',
      [decoded.userId, 'active']
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶不存在或已被停用'
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

// 角色授權中間件
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

// 用戶註冊
app.post(`${API_PREFIX}/auth/register`, async (req, res) => {
  try {
    const { username, password, role = 'viewer', full_name, email, phone } = req.body;
    
    // 驗證輸入
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供用戶名和密碼'
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error: '密碼太短',
        message: '密碼至少需要8個字符'
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
      `INSERT INTO users (username, password_hash, role, full_name, email, phone, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, username, role, full_name, email, phone, status, created_at`,
      [username, hashedPassword, role, full_name, email, phone, 'active']
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
          email: user.email,
          phone: user.phone,
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

// 用戶登入
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
      'SELECT * FROM users WHERE username = $1 AND status = $2',
      [username, 'active']
    );
    
    if (result.rows.length === 0) {
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
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶名或密碼錯誤'
      });
    }
    
    // 更新最後登入時間
    await pool.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );
    
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
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          full_name: user.full_name,
          email: user.email,
          phone: user.phone,
          status: user.status,
          last_login: user.last_login
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

// 獲取當前用戶信息
app.get(`${API_PREFIX}/auth/me`, authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, full_name, email, phone, status, 
              last_login, created_at, updated_at
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

// 獲取用戶列表（需要 super_admin）
app.get(`${API_PREFIX}/users`, authenticate, authorize('super_admin'), async (req, res) => {
  try {
    const { page = 1, limit = 20, role, status, search } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `SELECT id, username, role, full_name, email, phone, status, 
                        last_login, created_at, updated_at
                 FROM users WHERE 1=1`;
    const params = [];
    let paramIndex = 1;
    
    if (role) {
      query += ` AND role = $${paramIndex}`;
      params.push(role);
      paramIndex++;
    }
    
    if (status) {
      query += ` AND status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }
    
    if (search) {
      query += ` AND (username ILIKE $${paramIndex} OR full_name ILIKE $${paramIndex} OR email ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));
    
    const result = await pool.query(query, params);
    
    // 獲取總數
    const countQuery = query.replace(/SELECT.*FROM/, 'SELECT COUNT(*) as count FROM').split('ORDER BY')[0];
    const countResult = await pool.query(countQuery, params.slice(0, -2));
    const total = parseInt(countResult.rows[0].count);
    
    res.json({
      success: true,
      data: {
        users: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1
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

// 創建物業（需要 admin）
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
    
    // 檢查物業名稱是否已存在
    const existingProperty = await pool.query(
      'SELECT id FROM properties WHERE name = $1',
      [name]
    );
    
    if (existingProperty.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: '物業已存在',
        message: '物業名稱已存在'
      });
    }
    
    const result = await pool.query(
      `INSERT INTO properties (name, address, owner_name, owner_phone)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, address, owner_name, owner_phone]
    );
    
    const property = result.rows[0];
    
    // 記錄操作日誌
    await pool.query(
      `INSERT INTO operation_logs (user_id, action_type, resource_type, resource_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.userId, 'create_property', 'property', property.id, JSON.stringify({ name })]
    );
    
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

// 獲取物業列表
app.get(`${API_PREFIX}/properties`, authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `SELECT * FROM properties WHERE 1=1`;
    const params = [];
    let paramIndex = 1;
    
    if (search) {
      query += ` AND (name ILIKE $${paramIndex} OR address ILIKE $${paramIndex} OR owner_name ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));
    
    const result = await pool.query(query, params);
    
    // 獲取總數
    const countQuery = query.replace(/SELECT.*FROM/, 'SELECT COUNT(*) as count FROM').split('ORDER BY')[0];
    const countResult = await pool.query(countQuery, params.slice(0, -2));
    const total = parseInt(countResult.rows[0].count);
    
    res.json({
      success: true,
      data: {
        properties: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1
        }
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

// 404 處理
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `找不到路徑: ${req.path}`
  });
});

// 錯誤處理
app.use((err, req, res, next) => {
  console.error('伺服器錯誤:', err);
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: '伺服器內部錯誤'
  });
});

// 啟動伺服器
app.listen(port, () => {
  console.log(`🚀 混合版本伺服器啟動！`);
  console.log(`🌐 訪問: http://localhost:${port}`);
  console.log(`✅ 健康檢查: http://localhost:${port}/health`);
  console.log(`📚 API 文檔: http://localhost:${port}/api-docs`);
  console.log(`🔑 註冊端點: POST http://localhost:${port}${API_PREFIX}/auth/register`);
  console.log(`🔑 登入端點: POST http://localhost:${port}${API_PREFIX}/auth/login`);
  console.log(`\n📝 必需環境變數:`);
  console.log(`   JWT_SECRET=你的密鑰`);
  console.log(`   DATABASE_URL=PostgreSQL連接字串`);
  console.log(`   (Zeabur 會自動提供 DATABASE_URL)`);
});
